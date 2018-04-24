/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 * Notifications and licenses are retained for attribution purposes only
 *
 * Copyright (c) 2011, Atheros Communications Inc.
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
 * LMAC offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "ol_if_athutf.h"
#include <osdep.h>
#include <hif.h>
#include "bmi.h"
#include "sw_version.h"
#include "targaddrs.h"
#include "ol_helper.h"
#include "cdp_txrx_cmn.h"
#include "qdf_lock.h"  /* qdf_spinlock_* */
#include "qdf_types.h" /* qdf_vprint */
#include "qdf_util.h" /* qdf_vprint */
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include "wmi_unified_api.h"

#ifdef QCA_PARTNER_PLATFORM
#include "ol_txrx_peer_find.h"
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif
/* FIX THIS: the HL vs. LL selection will need to be done
 * at runtime rather than compile time
 */

#if defined(CONFIG_HL_SUPPORT)
#include "wlan_tgt_def_config_hl.h"    /* TODO: check if we need a seperated config file */
#else
#include "wlan_tgt_def_config.h"
#endif
#include "dbglog_host.h"
#include "ol_if_wow.h"
#include "a_debug.h"
#include "epping_test.h"

#if ATH_SUPPORT_DFS
#include "ol_if_dfs.h"
#endif

#if ATH_DEBUG
#include "osif_private.h"
#endif

#include "pktlog_ac.h"
#include "ol_regdomain.h"

#include "ol_if_me.h"
#if ATH_SUPPORT_SPECTRAL
#include "ol_if_spectral.h"
#endif
#include "ol_ath.h"

#if ATH_SUPPORT_GREEN_AP
#include "ol_if_greenap.h"
#endif  /* ATH_SUPPORT_GREEN_AP */

#include "ol_if_stats.h"
#include "ol_ratetable.h"
#include "ol_if_vap.h"
#include "wds_addr.h"
#include "ol_if_smart_ant.h"

#if ATH_SUPPORT_FIPS
#include "qdf_atomic.h"
#endif
#if ATH_SUPPORT_CODESWAP
#include "ol_swap.h"
#endif

#include "ol_if_eeprom.h"
#include "ol_txrx_types.h"
#if ATH_PERF_PWR_OFFLOAD

#include "ath_pci.h"
#include <linux/fs.h>
#include <linux/gpio.h>
#ifndef __LINUX_POWERPC_ARCH__
#include <asm/segment.h>
#endif
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include "reg_struct.h"
#include "regtable.h"

#if UMAC_SUPPORT_ACFG
#include "ieee80211_acfg.h"
#include <acfg_event_types.h>   /* for ACFG_WDT_TARGET_ASSERT */
#endif

#if WIFI_MEM_MANAGER_SUPPORT
#include "mem_manager.h"
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif

#ifdef QCA_PARTNER_PLATFORM
extern struct ol_txrx_ast_entry_t *
ol_txrx_ast_find_hash_find(
        struct ol_txrx_pdev_t *pdev,
        u_int8_t *peer_mac_addr,
        int mac_addr_is_aligned);
extern struct ol_txrx_peer_t *
ol_txrx_peer_find_by_id(
    struct ol_txrx_pdev_t *pdev,
    u_int16_t peer_id);
#endif

static u_int8_t
ol_ath_get_emiwar_80p80_defval(struct ol_ath_softc_net80211 *scn);
void ieee80211_buffull_handler(struct ieee80211com *ic);
void wmi_proc_create(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id);
void wmi_proc_remove(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id);
#ifdef ATH_AHB
QDF_STATUS hif_diag_read_soc_ipq4019(struct hif_opaque_softc *hif_device,
			uint32_t address, uint8_t *data, int nbytes);
#endif
int osif_ol_ll_vap_hardstart(struct sk_buff *skb, struct net_device *dev);
static void
ol_update_txpow_vdev(ol_txrx_vdev_handle vdev, uint8_t subtype,uint8_t transmit_power);
void ol_ath_check_btcoex_support(struct ol_ath_softc_net80211 *scn);
void ol_ath_check_bandfilter_switch_gpio_support(struct ol_ath_softc_net80211 *scn);

#ifdef CONFIG_AR900B_SUPPORT

/* TODO this section need to be used when linux kernel memory for crash
 * scope is increased
 */

#define FW_DUMP_FILE_QCA9888      "/lib/firmware/WLAN_FW_9888.BIN"
#define FW_DUMP_FILE_QCA9984      "/lib/firmware/WLAN_FW_9984.BIN"
#define FW_DUMP_FILE_AR900B       "/lib/firmware/WLAN_FW_900B.BIN"
#define FW_DUMP_FILE_AR9888       "/lib/firmware/WLAN_FW_9888.BIN"
#define FW_DUMP_FILE_IPQ4019      "/lib/firmware/WLAN_FW_IPQ4019.BIN"

#define DEFAULT_MGMT_RETRY_LIMIT (4)

// Disabling scan offload
#define UMAC_SCAN_OFFLOAD 1
#if defined(EPPING_TEST) && !defined(HIF_USB)
unsigned int eppingtest = 1;
unsigned int bypasswmi = 1;
#else
unsigned int eppingtest = 0;
unsigned int bypasswmi = 0;
#endif

#ifndef REMOVE_INIT_DEBUG_CODE
int wmi_init_flag = 0;
EXPORT_SYMBOL(wmi_init_flag);
#endif

#define FILE_PATH_LEN 128

#define LOW_MEM_SYSTEM_RAM              (131072)                     // 131072Kb

int ol_ath_pdev_tpc_config_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_gpio_input_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_nf_dbr_dbm_info_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_packet_power_info_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_generic_buffer_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_mcast_list_ageout_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_peer_mumimo_tx_count_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_peer_gid_userpos_list_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_pdev_caldata_version_check_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);

#if QCA_AIRTIME_FAIRNESS
int ol_ath_atf_peer_stats_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
int ol_ath_tx_data_traffic_ctrl_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen);
#endif

unsigned int allocram_track_max = 0;
module_param(allocram_track_max, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(allocram_track_max,
        "Enable target allocram tracking");
EXPORT_SYMBOL(allocram_track_max);

unsigned int max_clients = CFG_MAX_CLIENTS;
module_param(max_clients, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(max_clients);

unsigned int max_vaps = CFG_MAX_VAPS;
module_param(max_vaps, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(max_vaps);

extern uint32_t otp_mod_param;
#if ATH_SUPPORT_LOWI
extern int ol_ath_lowi_data_req_to_fw(struct ieee80211com *ic, int msg_len, void *req, int msgsubType);
#endif
unsigned int fw_dump_options = FW_DUMP_TO_CRASH_SCOPE;
module_param(fw_dump_options, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(fw_dump_options);

unsigned int enable_mesh_support = 0;
module_param(enable_mesh_support, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
EXPORT_SYMBOL(enable_mesh_support);

extern u_int8_t prealloc_disabled;

#if OL_ATH_SUPPORT_LED
static OS_TIMER_FUNC(ol_ath_led_blink_timed_out);
static OS_TIMER_FUNC(ol_ath_led_poll_timed_out);

/* 50Mbps per entry */
bool ipq4019_led_initialized = 0;
uint32_t ipq4019_led_type = 0;      /* ipq40xx gpio or led source type */

static const
OL_LED_BLINK_RATES ol_led_blink_rate_table[] = {
    {  500, 130 },
    {  400, 100 },
    {  280,  70 },
    {  240,  60 },
    {  200,  50 },
    {  160,  40 },
    {  130,  30 },
    {  100,  30 },
    {  90,  20 },
    {  80,  20 },
    {  70,  20 },
    {  60,  10 },
    {  50,  10 },
    {  40,  10 },
};

#endif


enum {
    FW_MEM_HIGH_PRIORITY = 0, /* This memory requires continuos memory allcation */
    FW_MEM_LOW_PRIORITY,      /* This memory can be fragmented */
    FW_PRIORITY_MAX
};

#ifdef AH_CAL_IN_FLASH_PCI
extern u_int32_t CalAddr[];
extern int pci_dev_cnt;
#endif

extern int whal_mcs_to_kbps(int, int, int, int);
extern void ol_if_mgmt_drain(struct ieee80211_node *ni, int force);
extern int32_t ol_ath_thermal_mitigation_detach(struct ol_ath_softc_net80211 *scn,
                                              struct net_device *dev);
extern int32_t ol_ath_thermal_mitigation_attach(struct ol_ath_softc_net80211 *scn,
                                              struct net_device *dev);

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
extern int ath_net80211_add_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
extern int ath_net80211_del_hmmc(struct ieee80211vap *vap, u_int32_t ip, u_int32_t mask);
extern void ath_net80211_buffull_handler(struct ieee80211com *ic);
#endif

#if DBDC_REPEATER_SUPPORT
extern struct global_ic_list ic_list;
#endif

static int
ol_ath_dcs_interference_handler (ol_scn_t scn,
			  u_int8_t *data, u_int16_t datalen);

int ol_ath_target_stop(struct ieee80211com *ic);
extern int emu_type;
extern int ath_get_radio_index(struct net_device *netdev);
extern int asf_adf_attach(void);
extern void dfs_reset(struct ieee80211com *ic);
extern void ieee80211_dfs_reset(struct ieee80211com *ic);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
extern int global_radio_id;
extern unsigned int nss_wifi_olcfg;
#endif

bool
ol_ath_get_host_hybrid_mode(ol_scn_t scn)
{
    return scn->hybrid_mode;
}

uint32_t
ol_ath_get_host_pltfrm_mode(ol_scn_t scn)
{

    switch(scn->target_type)
    {
        case TARGET_TYPE_AR6002:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_AR6003:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_AR6004:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_AR6006:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_AR9888:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_AR6320:
            return HOST_PLATFORM_LOW_PERF;
#if PEER_FLOW_CONTROL_FORCED_MODE0
        case TARGET_TYPE_AR900B:
            return HOST_PLATFORM_LOW_PERF_NO_FETCH;
        case TARGET_TYPE_QCA9984:
            return HOST_PLATFORM_LOW_PERF_NO_FETCH;
        case TARGET_TYPE_QCA9888:
            return HOST_PLATFORM_LOW_PERF_NO_FETCH;
#elif MIPS_LOW_PERF_SUPPORT
        case TARGET_TYPE_AR900B:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_QCA9984:
            return HOST_PLATFORM_LOW_PERF;
        case TARGET_TYPE_QCA9888:
            return HOST_PLATFORM_LOW_PERF;
#else
        case TARGET_TYPE_AR900B:
            return HOST_PLATFORM_HIGH_PERF;
        case TARGET_TYPE_QCA9984:
            return HOST_PLATFORM_HIGH_PERF;
        case TARGET_TYPE_QCA9888:
            return HOST_PLATFORM_HIGH_PERF;
#endif
        case TARGET_TYPE_IPQ4019:
            return HOST_PLATFORM_HIGH_PERF;
        default:
            qdf_print("!!! Invalid Target Type %d !!!\n", scn->target_type);
            return -EINVAL;
    }
    return EOK;
}


__inline__
u_int32_t host_interest_item_address(u_int32_t target_type, u_int32_t item_offset)
{
    switch (target_type)
    {
        default:
            ASSERT(0);
        case TARGET_TYPE_AR6002:
            return (AR6002_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6003:
            return (AR6003_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6004:
            return (AR6004_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6006:
            return (AR6006_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR9888:
            return (AR9888_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR6320:
            return (AR6320_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_AR900B:
            return (AR900B_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_QCA9984:
            return (QCA9984_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_QCA9888:
            return (QCA9888_HOST_INTEREST_ADDRESS + item_offset);
        case TARGET_TYPE_IPQ4019:
            return (IPQ4019_HOST_INTEREST_ADDRESS + item_offset);
    }
}

/* WORDs, derived from AR600x_regdump.h */
#define REG_DUMP_COUNT_AR9888   60
#define REG_DUMP_COUNT_AR6320   60
#define REG_DUMP_COUNT_AR900B   60
#define REG_DUMP_COUNT_QCA9984  60
#define REG_DUMP_COUNT_QCA9888  60
#define REGISTER_DUMP_LEN_MAX   60

#if REG_DUMP_COUNT_AR9888 > REGISTER_DUMP_LEN_MAX
#error "REG_DUMP_COUNT_AR9888 too large"
#endif

#if REG_DUMP_COUNT_AR6320 > REGISTER_DUMP_LEN_MAX
#error "REG_DUMP_COUNT_AR6320 too large"
#endif

#if REG_DUMP_COUNT_AR900B > REGISTER_DUMP_LEN_MAX
#error "REG_DUMP_COUNT_AR900B too large"
#endif

#if REG_DUMP_COUNT_QCA9984 > REGISTER_DUMP_LEN_MAX
#error "REG_DUMP_COUNT_QCA9984 too large"
#endif

#if REG_DUMP_COUNT_QCA9888 > REGISTER_DUMP_LEN_MAX
#error "REG_DUMP_COUNT_QCA9888 too large"
#endif

uint8_t board_id = 0, chipid = 0;

struct file* file_open(const char* path, int flags, int rights)
{
	struct file* filp = NULL;
	mm_segment_t oldfs;
	int err = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if(IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

void file_close(struct file* file) {
	filp_close(file, NULL);
}

int
file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(file, data, size, &offset);
	if(ret < 0)
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n FAILED TO WRITE %d\n", ret);

	set_fs(oldfs);
	return ret;
}

int
read_file(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_read(file, data, size, &offset);
	if(ret < 0)
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n FAILED TO READ %d\n", ret);

	set_fs(oldfs);
	return ret;
}

static int
get_fileindex(char *tmpbuf)
{
	struct file *file;

	file = file_open("/lib/firmware/.fileindex", O_RDONLY, 00644);
	if(file == NULL){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d No index file, starting @ 1 \n", __func__, __LINE__);
        *tmpbuf=1;
        return 0;
	}
	read_file(file, 0, tmpbuf, 10);
	file_close(file);
	return 0;
}

int filesnotexist = 0;
#define MAX_FILENAMES_SIZE 1024 * 4 //File list names len

static int
get_filenames(u_int32_t target_type,char *tmpbuf, int size)
{
    struct file *file = NULL;
    int ret;

    switch (target_type)
    {
        case TARGET_TYPE_AR900B:
            if (chipid == 0) {
		file = file_open("/lib/firmware/AR900B/hw.1/.filenames", O_RDONLY, 00644);
            } else if (chipid == 1) {
	        file = file_open("/lib/firmware/AR900B/hw.2/.filenames", O_RDONLY, 00644);
	    } else {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Chip id %d is not supported for AR900B!\n",__func__, chipid);
	        return -1;
	    }
	    break;
        case TARGET_TYPE_QCA9984:
	    if (chipid == 0) {
		file = file_open("/lib/firmware/QCA9984/hw.1/.filenames", O_RDONLY, 00644);
            } else {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Chip id %d is not supported for QCA9984!\n",__func__, chipid);
		return -1;
	    }
	    break;
	default:
	    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Target type %u is not supported.\n", __func__,target_type);
	    return -1;
    }
    if(file == NULL){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Failed to open board data file list for chip id %d!\n", __func__, chipid);
        return -1;
    }
    /* Why ignore the return value of read_file()? It returns the number of
     * bytes that have been read. This is the number of valid bytes in the
     * buffer and exactly the number we need for the loop condition in
     * boardid_to_filename() */
    ret = read_file(file, 0, tmpbuf, size);
    file_close(file);
    return ret;
}

static int
boardid_to_filename(struct ol_ath_softc_net80211 *scn, int id, char *tmpbuf, int buflen, char *boarddata_file)
{
    int i, startindex = 0;
    char idstr[5] = {0};
    char *srcptr, *destptr;
    long result = 0;
    int len = 0, found = -1;
    startindex = 0;

    for(i = 0; i < (buflen - 4); i++){
        if(tmpbuf[i] == '.') {
            idstr[0]= tmpbuf[i-3];
            idstr[1]= tmpbuf[i-2];
            idstr[2]= tmpbuf[i-1];
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
            strict_strtol(idstr, 0, &result);
#else
            /* As we are reading arbitrary file content, it is not unlikely that
             * kstrtol fails. Therefore check the return value. */
            if (kstrtol(idstr, 10, &result) != 0) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Failed to convert '%s' to integer!\n", __func__, idstr);
                return -1;
            }
#endif
            if(result == id && result != 0){
                srcptr = &tmpbuf[startindex];
                destptr = &boarddata_file[0];
                len    = i + 4 - startindex;
                qdf_str_lcopy(destptr, srcptr, len + 1);
                boarddata_file[i + 4 - startindex] = '\0';
                found = 1;
                break;
            }
            else{
                i+=4;
                startindex = i + 1;
                continue;
            }
        }/* buffer */
    } /* for loop */
    /*
     * instead of silently falling back to a default image. Otherwise we may run
     *        * into issues during operation that unnecessarily consume debugging
     *               * resources because they are very hard to relate to wrong board data. */
    if (found != 1) {
        if (scn->target_type == TARGET_TYPE_IPQ4019) {
            destptr = &boarddata_file[0];
            switch(id)
            {
                case DK01_2G_Y9803:
                    srcptr = IPQ4019_DK01_Y9803_2G_BOARD_DATA_FILE;
                    break;
                case DK01_5G_Y9803:
                    srcptr = IPQ4019_DK01_Y9803_5G_BOARD_DATA_FILE;
                    break;
                case DK03_2G:
                    srcptr = IPQ4019_DK03_2G_BOARD_DATA_FILE;
                    break;
                case DK03_5G:
                    srcptr = IPQ4019_DK03_5G_BOARD_DATA_FILE;
                    break;
                case DK04_2G:
                    srcptr = IPQ4019_DK04_2G_BOARD_DATA_FILE;
                    break;
                case DK04_5G:
                    srcptr = IPQ4019_DK04_5G_BOARD_DATA_FILE;
                    break;
                case DK04_NEGATIVE_POWER_2G:
                    srcptr = IPQ4019_DK04_NEGATIVE_POWER_2G_BOARD_DATA_FILE;
                    break;
                case DK04_NEGATIVE_POWER_5G:
                    srcptr = IPQ4019_DK04_NEGATIVE_POWER_5G_BOARD_DATA_FILE;
                    break;
                case DK03_YA131_2G:
                    srcptr = IPQ4019_DK03_YA131_2G_BOARD_DATA_FILE;
                    break;
                case DK03_YA131_5G:
                    srcptr = IPQ4019_DK03_YA131_5G_BOARD_DATA_FILE;
                    break;
                case DK05_2G:
                    srcptr = IPQ4019_DK05_2G_BOARD_DATA_FILE;
                    break;
                case DK05_5G:
                    srcptr = IPQ4019_DK05_5G_BOARD_DATA_FILE;
                    break;
                case DK07_2G:
                    srcptr = IPQ4019_DK07_2G_BOARD_DATA_FILE;
                    break;
                case DK07_5G_HB:
                    srcptr = IPQ4019_DK07_5G_HB_BOARD_DATA_FILE;
                    break;
                case DK07_5G_LB:
                    srcptr = IPQ4019_DK07_5G_LB_BOARD_DATA_FILE;
                    break;
                case DK06_2G:
                    srcptr = IPQ4019_DK06_2G_BOARD_DATA_FILE;
                    break;
                case DK06_5G:
                    srcptr = IPQ4019_DK06_5G_BOARD_DATA_FILE;
                    break;

                default:
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Warning : No board id matched. Selecting default boarddata file\n");
                    if(!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5))
                        srcptr = "boarddata_0.bin";
                    else
                        srcptr = "boarddata_1.bin";
                    break;
            }
            qdf_str_lcopy(destptr, srcptr, strlen(srcptr) + 1);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s: Selecting board data file name %s\n",scn->sc_osdev->netdev->name, destptr);
        }
        else if (scn->target_type == TARGET_TYPE_QCA9984) {
            destptr = &boarddata_file[0];
            if(!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5)) {
                qdf_str_lcopy(destptr, "boarddata_0.bin", 16);
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n wifi0: Selecting board data file name %s\n", destptr);
            } else if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi1", 5)) {
                qdf_str_lcopy(destptr, "boarddata_1.bin", 16);
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n wifi1: Selecting board data file name %s\n", destptr);
            } else if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi2", 5)) {
                qdf_str_lcopy(destptr, "boarddata_2.bin", 16);
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n wifi2: Selecting board data file name %s\n", destptr);
            } else {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Unable to map board data file for unknown device "
                       "%s\n",
                       scn->sc_osdev->netdev->name);
                return -1;
            }
        } else if (scn->target_type == TARGET_TYPE_QCA9888){
            destptr = &boarddata_file[0];
            switch(id)
            {
                case QCA9888_Y9690_VER2:
                    srcptr = QCA9888_Y9690_VER2_BOARD_DATA_FILE;
                    break;
                case QCA9888_Y9484_VER2:
                    srcptr = QCA9888_Y9484_VER2_BOARD_DATA_FILE;
                    break;
                case QCA9888_Y9582_VER2:
                    srcptr = QCA9888_Y9582_VER2_BOARD_DATA_FILE;
                    break;
                case QCA9888_Y9690_VER2_SBS_HB:
                    srcptr = QCA9888_Y9690_VER2_SBS_HB_BOARD_DATA_FILE;
                    break;
                case QCA9888_YA105_VER2:
                    srcptr = QCA9888_YA105_VER2_BOARD_DATA_FILE;
                    break;
                case QCA9888_YA841_VER2:
                    srcptr = QCA9888_YA841_VER2_BOARD_DATA_FILE;
                    break;
                default:
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Warning : No board id matched. Selecting default boarddata file\n");
                    srcptr = "boarddata_0.bin";
                    break;
            }

            qdf_str_lcopy(destptr, srcptr, strlen(srcptr) + 1);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n %s: Selecting board data file name %s\n",scn->sc_osdev->netdev->name, destptr);
	}else {
#if DEFAULT_BOARD_DATA
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n ******************************************* CAUTION!! ************************************************\n");
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Invalid BoardId! Did not find board data file for board id %d\n", __func__, id);
            destptr = &boarddata_file[0];
            if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi0", 5)) {
                qdf_str_lcopy(destptr, DEFAULT_BOARDDATA_FILE_5G, strlen(DEFAULT_BOARDDATA_FILE_5G) + 1);
            } else if (!qdf_mem_cmp(scn->sc_osdev->netdev->name, "wifi1", 5)) {
                qdf_str_lcopy(destptr, DEFAULT_BOARDDATA_FILE_2G, strlen(DEFAULT_BOARDDATA_FILE_2G) + 1);
            } else {
                qdf_str_lcopy(destptr, DEFAULT_BOARDDATA_FILE_5G, strlen(DEFAULT_BOARDDATA_FILE_5G) + 1);
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n ******************************LOADING DEFAULT BOARD DATA FILE************************\n");

#else
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Did not find board data file for board id %d\n", __func__, id);
            return -1;
#endif
        }
    }


return 0;

}

static int
update_fileindex(int fileindex)
{
	struct file *file;
	char tmpbuf[20] = {-1};

	file = file_open("/lib/firmware/.fileindex", O_RDONLY, 00644);
	if(file == NULL){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d Cannot open the index file \n", __func__, __LINE__);
		file = file_open("/lib/firmware/.fileindex", O_CREAT|O_WRONLY|O_TRUNC, 00644);
		if(file == NULL) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d Cannot open the index file \n", __func__, __LINE__);
			return -1;
        }
	}

	file_close(file);
	file = file_open("/lib/firmware/.fileindex", O_EXCL|O_WRONLY, 00644);

        snprintf(tmpbuf, sizeof(tmpbuf), "%c\n",fileindex);
    if (file) {
        file_write(file, 0, tmpbuf, 4);
        file_close(file);
    }
    return 0;
}
#endif /* CONFIG_AR900B_SUPPORT */

/* wow_nack is a param used by MCL's callback */
void
ol_target_send_suspend_complete(void *ctx, bool wow_nack)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)ctx;

    scn->is_target_paused = TRUE;
    __ol_target_paused_event(scn);
}

#define SOC_PCIE_REGBASE 0x81030
#define PCIE_BAR0_MASK 0xfffff
int ol_diag_read_sram(struct hif_opaque_softc *hif_ctx, unsigned int sram_base,
		void *dst, size_t len)
{
	int i=0;
	unsigned int target_bar0;

	if (!dst)
		return -ENOMEM;
	/* get the bar0 from target register */

	target_bar0 = hif_reg_read(hif_ctx, SOC_PCIE_REGBASE);

	/* clear off the bits 0-19 */
	target_bar0 = target_bar0 & ~PCIE_BAR0_MASK;

	for (i=0; i < len; i+=4) {
		hif_reg_write(hif_ctx, 0x4d00c, target_bar0+sram_base+i);
		*(unsigned int*)dst = hif_reg_read(hif_ctx, 0x4d010);
		dst += 4;
	}
	return EOK;
}

#ifdef BIG_ENDIAN_HOST
void swap_bytes(void *pv, size_t n)
{
       int noWords;
       int i;
       A_UINT32 *wordPtr;

       noWords =   n/sizeof(u_int32_t);
       wordPtr = (u_int32_t *)pv;
       for (i=0;i<noWords;i++)
       {
               *(wordPtr + i) = __cpu_to_le32(*(wordPtr + i));
       }
}
#define SWAPME(x, len) swap_bytes(&x, len);
#endif

/*
 * Debugging Target Crash Log only: Do not modify anything
 */
struct fw_ram_dump {
        /* Take highest Length here Currently DRAM */
        A_UINT8 dram[FW_DRAM_LENGTH_QCA9984];
        A_UINT8 sram[FW_SRAM_LENGTH];
        A_UINT8 iram[FW_IRAM_LENGTH];
        A_UINT8 apb_reg_space[HW_APB_REG_LENGTH];
        A_UINT8 wifi_reg_space[HW_WIFI_REG_LENGTH];
        A_UINT8 ce_reg_space[HW_CE_REG_LENGTH];
        A_UINT8 soc_reg_space[SOC_REG_LENGTH];
        A_UINT8 apb_reg_space1[HW_APB_REG_LENGTH1];
};
enum {
    FW_DRAM_IDX=0,
    FW_SRAM_IDX,
    FW_IRAM_IDX,
    FW_APB0_REG_IDX,
    FW_WIFI_REG_IDX,
    FW_CE_REG_IDX,
    FW_SOC_REG_IDX,
    FW_APB1_REG_IDX,
    FW_REG_MAX
};
struct fw_ram_dump_map {
    A_UINT32 address;
    A_UINT32 length;
    A_UINT8  skip;
    QDF_STATUS (*CustomHIFDiagReadMem)(struct hif_opaque_softc *hif_device, uint32_t sourceaddr, uint8_t *destbuf, int nbytes);

} fw_ram_dump_map_AR9888 [FW_REG_MAX] = {
    /* address in fw    length              skip */
    {FW_DRAM_ADDRESS,   FW_DRAM_LENGTH_AR9888,0, NULL},
    {FW_SRAM_ADDRESS,   FW_SRAM_LENGTH,     0,  NULL},
    {FW_IRAM_ADDRESS,   FW_IRAM_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE,  HW_APB_REG_LENGTH,  0,  NULL},
    {HW_WIFI_REG_SPACE, HW_WIFI_REG_LENGTH, 0,  NULL},
    {HW_CE_REG_SPACE,   HW_CE_REG_LENGTH,   0,  NULL},
    {SOC_REG_SPACE,     SOC_REG_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE1, HW_APB_REG_LENGTH1, 0,  NULL}
},
fw_ram_dump_map_AR900B [FW_REG_MAX] = {
    /* address in fw    length              skip */
    {FW_DRAM_ADDRESS,   FW_DRAM_LENGTH_AR900B,0, NULL},
    {FW_SRAM_ADDRESS,   FW_SRAM_LENGTH,     0,  NULL},
    {FW_IRAM_ADDRESS,   FW_IRAM_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE,  HW_APB_REG_LENGTH,  0,  NULL},
    {HW_WIFI_REG_SPACE, HW_WIFI_REG_LENGTH, 0,  NULL},
    {HW_CE_REG_SPACE,   HW_CE_REG_LENGTH,   0,  NULL},
    {SOC_REG_SPACE,     SOC_REG_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE1, HW_APB_REG_LENGTH1, 0,  NULL}
},
fw_ram_dump_map_QCA9984 [FW_REG_MAX] = {
    /* address in fw    length              skip */
    {FW_DRAM_ADDRESS,   FW_DRAM_LENGTH_QCA9984,0, NULL},
    {FW_SRAM_ADDRESS,   FW_SRAM_LENGTH,     0,  NULL},
    {FW_IRAM_ADDRESS,   FW_IRAM_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE,  HW_APB_REG_LENGTH,  0,  NULL},
    {HW_WIFI_REG_SPACE, HW_WIFI_REG_LENGTH, 0,  NULL},
    {HW_CE_REG_SPACE,   HW_CE_REG_LENGTH,   0,  NULL},
    {SOC_REG_SPACE,     SOC_REG_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE1, HW_APB_REG_LENGTH1, 0,  NULL}
}
#ifdef ATH_AHB
,
fw_ram_dump_map_IPQ4019 [FW_REG_MAX] = {
    /* address in fw    length              skip */
    {FW_DRAM_ADDRESS,   FW_DRAM_LENGTH_IPQ4019,0, NULL},
    {FW_SRAM_ADDRESS,   FW_SRAM_LENGTH,     0,  NULL},
    {FW_IRAM_ADDRESS,   FW_IRAM_LENGTH,     0,  NULL},
    {HW_APB_REG_SPACE,  HW_APB_REG_LENGTH,  0,  NULL},
    {HW_WIFI_REG_SPACE, HW_WIFI_REG_LENGTH, 0,  NULL},
    {HW_CE_REG_SPACE,   HW_CE_REG_LENGTH,   0,  NULL},
    {SOC_REG_SPACE,   SOC_REG_LENGTH,     0,    hif_diag_read_soc_ipq4019},
    {HW_APB_REG_SPACE1, HW_APB_REG_LENGTH1, 0,  NULL}
}
#endif
;

char radioasserted[2] = {0,0};
/*
 * This function creates the core dump either into file or pre-allocated
 * memory or into both.
 */
static void
fw_get_core_dump(struct ol_ath_softc_net80211 *ramdump_scn, A_INT8 *file_path,
        A_UINT32 d_opts)
{
    struct file *file = NULL;
    A_UINT32 length, i=0;
    A_UINT32 address;
    void *crash_scope_addr = NULL;      /* for dumping to crash scope */
    void *scratch_buf =  NULL;          /* srach buffer for copying*/
    void *scratch_buf_start =  NULL;
    A_UINT32 dump_to_file  = d_opts & FW_DUMP_TO_FILE;
    A_UINT32 dump_to_scope =  d_opts & FW_DUMP_TO_CRASH_SCOPE;
    A_UINT32 n_file_wr_offset = 0;
    A_UINT32 n_buf_wr_offset = 0;
    int dump_to_scope_ovf = 0;
    struct fw_ram_dump_map *fw_ram_dump_map_cmn = NULL;
    A_UINT32 fw_io_mem_addr_l = 0;
    A_UINT32 fw_io_mem_size_l = 0;
    int fw_dump_max_idx = 0;
    A_STATUS status=0;
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) && !(ATH_SUPPORT_FW_RAM_DUMP_FOR_MIPS))
    int ret = 0;
    struct device_node *dev_node=NULL;
    unsigned int registerdetails[2];
#endif

#define MAX_ADAPTIVE_BUFF_LEN   1024
#define MIN_ADAPTIVE_BUFF_LEN   128
    int print_scope = 0;
    int block_size = 0;
    int remaining = 0, coreid = 0;
    int adaptive_buff_len = MAX_ADAPTIVE_BUFF_LEN;
    struct hif_opaque_softc *hif_hdl = NULL;
    int full_mem_alloced = 0;
    int total_mem_length = 0;

    if (!ramdump_scn) {
        qdf_print("ramdump scn is NULL\n");
        qdf_target_assert_always(0);
        return;
    }

    hif_hdl = ( struct hif_opaque_softc *)ramdump_scn->hif_hdl;

    if (!hif_hdl) {
        qdf_print("hif handle is NULL: %s \n", __func__);
        return;
    }

    if (ramdump_scn->target_type == TARGET_TYPE_AR9888) {
       fw_ram_dump_map_cmn = (struct fw_ram_dump_map *)&fw_ram_dump_map_AR9888;
    } else if (ramdump_scn->target_type == TARGET_TYPE_QCA9984 || ramdump_scn->target_type == TARGET_TYPE_QCA9888) {
       fw_ram_dump_map_cmn = (struct fw_ram_dump_map *)&fw_ram_dump_map_QCA9984;
    }
#ifdef ATH_AHB
    else if (ramdump_scn->target_type == TARGET_TYPE_IPQ4019) {
       fw_ram_dump_map_cmn = (struct fw_ram_dump_map *)&fw_ram_dump_map_IPQ4019;
    }
#endif
    else {
       fw_ram_dump_map_cmn = (struct fw_ram_dump_map *)&fw_ram_dump_map_AR900B;
    }

    /* check if user requested for file, if so do dump to file */
    if (dump_to_file) {
        if (!file_path) {
            dump_to_file = 0;
        } else {
            file = file_open(file_path, O_CREAT | O_WRONLY | O_TRUNC, 00644);
            if (!file) {
                dump_to_file = 0;
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "** %s: file open failure %s\n", __func__, file_path);
            }
        }
    }

    /* Get crashdump mem addr and size */
#if ATH_SUPPORT_FW_RAM_DUMP_FOR_MIPS
    /* MIPS PLATFORM */

    (void) coreid; // unused parameter
    if (dump_to_scope) {
        u_int32_t vmem_len = 0;

        if(ath79_get_wlan_fw_dump_buffer(&crash_scope_addr, &vmem_len) == -1) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Cannot access memory to dump WLAN Firmware data\n");
            goto error_1;
        }
        fw_io_mem_size_l = vmem_len;

        /* MIPS platform have just 2MB reserved for FW dump.
        Always use the first slot */
        n_buf_wr_offset = 0;
    }
#else
    /* ARM PLATFORM */
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    /* get fw io mem addr & size entries from dtsi file */
    dev_node = of_find_node_by_name (NULL, "wifi_dump");
    if(dev_node) {
        if((ret = of_property_read_u32_array(dev_node,"reg", &registerdetails[0], 2))) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error: While retrieving register details from the reg entry in wifi_dump. error %d\n",ret);
            qdf_target_assert_always(0);
            return;
        }
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: No  wifi_dump dts node available in the dts entry file\n");
        qdf_target_assert_always(0);
        return;
    }
    fw_io_mem_addr_l = registerdetails[0];
    fw_io_mem_size_l = registerdetails[1];

#else /* for linux version code < 3.14 */
    if (ramdump_scn->target_type == TARGET_TYPE_AR9888) {
        fw_io_mem_addr_l = FW_IO_MEM_ADDR_AR9888;
        fw_io_mem_size_l = FW_IO_MEM_SIZE_AR9888;
    } else if (ramdump_scn->target_type == TARGET_TYPE_QCA9984 || ramdump_scn->target_type == TARGET_TYPE_QCA9888) {
        fw_io_mem_addr_l = FW_IO_MEM_ADDR_AR900B;
        fw_io_mem_size_l = FW_IO_MEM_SIZE_AR900B;
    } else if (ramdump_scn->target_type == TARGET_TYPE_AR900B){
        fw_io_mem_addr_l = FW_IO_MEM_ADDR_AR900B;
        fw_io_mem_size_l = FW_IO_MEM_SIZE_AR900B;
    } else if (ramdump_scn->target_type == TARGET_TYPE_IPQ4019) {
        fw_io_mem_addr_l = FW_IO_MEM_ADDR_IPQ4019;
        fw_io_mem_size_l = FW_IO_MEM_SIZE_IPQ4019;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: unknown target type");
    }

#endif /* LINUX_VERSION_CODE */
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Retrived fw_io_mem_size_l = %x fw_io_mem_addr_l = %x\n",fw_io_mem_size_l,fw_io_mem_addr_l);

    if (fw_io_mem_size_l < (6 << 20)) {
        /* cannot assign slots as fw io memsize < 6MB, use slot0 only */
        coreid = 0;
        radioasserted[0] = 1;
        n_buf_wr_offset = 0;
    } else {
        if (!qdf_mem_cmp(ramdump_scn->sc_osdev->netdev->name, "wifi0", 5)) {
            coreid = 0;
            radioasserted[0] = 1;
        } else if (!qdf_mem_cmp(ramdump_scn->sc_osdev->netdev->name, "wifi1", 5)) {
            coreid = 1;
            radioasserted[1] = 1;
        } else if (!qdf_mem_cmp(ramdump_scn->sc_osdev->netdev->name, "wifi2", 5)) {
            if(radioasserted[0] != 1)
                coreid = 0;
            else if(radioasserted[1] != 1)
                coreid = 1;
            else {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: No space left to copy the target contents for this radio wifi2.Using 3rd Slot");
                coreid = 2;
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WARNING: No fixed crashdummp space defined yet to handle target assert for this radio wifi2\n");
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "For now, copying the target assert in  slot [%d]\n",coreid);
        } else {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: Invalid radio id\n");
            qdf_target_assert_always(0);
            return;
        }
        n_buf_wr_offset += (coreid * 0x200000); //choose the appropriate 2MB slot

        if((n_buf_wr_offset + 0x200000) > fw_io_mem_size_l) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR: Trying write beyond offset %x is invalid.  \n",fw_io_mem_size_l);
            qdf_target_assert_always(0);
            return;
        }
    }
    crash_scope_addr = (struct fw_ram_dump *)ioremap(fw_io_mem_addr_l, fw_io_mem_size_l);

#endif /* MIPS/ARM */

    /* check if dump_to_scope is required, if needed map the memory */
    if (dump_to_scope) {
        if (!crash_scope_addr) {
            dump_to_scope =  0;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "** %s: ioremap failure addr:0x%x, size:0x%x",
                   __func__, fw_io_mem_addr_l, fw_io_mem_size_l);
        } else {
            qdf_mem_set(crash_scope_addr+n_buf_wr_offset, 0x200000, 0); //reset the contents in the slot
        }
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Copying %s target assert at offset 0x%x\n",ramdump_scn->sc_osdev->netdev->name,n_buf_wr_offset);

    /* DRAM is the biggest memory chunk, get the memory of that size,
     * and reuse this buffer for every region
     */

    if (ramdump_scn->is_ar900b) {
        fw_dump_max_idx = FW_REG_MAX;
    } else {
        /* Dump only dram as it supports only dram */
        fw_dump_max_idx = FW_SRAM_IDX;
    }


    /* We will try to allocate MAX_ADAPTIVE_BUFF_LEN size off
     * scratch buffer for core dump generation. If it fails
     * beff length will be reduced to half and retried. This
     * scheme will try to allocat a maximum size buffer between
     * MAX_ADAPTIVE_BUFF_LEN and MIN_ADAPTIVE_BUFF_LEN.
     */
    /* Calculate total length */
    for (i = FW_DRAM_IDX; i < fw_dump_max_idx; i++)
    {
        total_mem_length += fw_ram_dump_map_cmn[i].length;
    }
    for (adaptive_buff_len = total_mem_length; adaptive_buff_len >= MIN_ADAPTIVE_BUFF_LEN;
         adaptive_buff_len >>= 1) {
        scratch_buf_start = scratch_buf = OS_MALLOC(ramdump_scn->sc_osdev, adaptive_buff_len, GFP_KERNEL);
        if (scratch_buf) {
            if (adaptive_buff_len == total_mem_length){
               full_mem_alloced = 1;
            }
            break;
        }
    }
    if (!scratch_buf) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "** Scratch buff allocation failure, Core dump will not be created\n");
        goto error_1;
    }

    if (dump_to_scope && crash_scope_addr) {
        print_scope = 1;
    }

    for (i = FW_DRAM_IDX; i < fw_dump_max_idx; i++)
    {
        address = fw_ram_dump_map_cmn[i].address;
        length = fw_ram_dump_map_cmn[i].length;
        remaining = length;
        block_size = adaptive_buff_len;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Copying target mem region[%d] 0x%X to crashscope location\n",i,address);
        if (!fw_ram_dump_map_cmn[i].skip) {
            while (remaining > 0){
                if (remaining < block_size) {
                    block_size = remaining;
                }
                qdf_mem_set(scratch_buf, block_size, 0);

                /* sram needs different handling */
                if (fw_ram_dump_map_cmn[i].CustomHIFDiagReadMem) {
                    status = (fw_ram_dump_map_cmn[i].CustomHIFDiagReadMem)(ramdump_scn->hif_hdl, address, (A_UCHAR*)scratch_buf, block_size);
                    if(status != A_OK) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CustomHIFDiagReadMem failed for region %d will contain zeros\n", i);
                    }
                }
                else {
                    if (FW_SRAM_IDX == i && ramdump_scn->target_type != TARGET_TYPE_IPQ4019) {
                        /* for SRAM, we do not need to worry about virt address,
                         * because that is going to be read as 32 bit words;
                         */
                        ol_diag_read_sram(hif_hdl, address, (A_UCHAR*)scratch_buf, block_size);
                    } else {
                        if (hif_diag_read_mem(hif_hdl, address,
                                    (A_UCHAR*)scratch_buf,
                                    block_size)!= QDF_STATUS_SUCCESS) {
                            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "hif_diag_read_mem failed for region %d will contain zeros\n", i);
                        }
                    }
                }
                if (print_scope && !dump_to_scope_ovf) {
                    if ((n_buf_wr_offset + block_size ) < fw_io_mem_size_l) {
                        qdf_mem_copy((A_UCHAR * )crash_scope_addr + n_buf_wr_offset, (A_UCHAR * )scratch_buf, block_size);
                        n_buf_wr_offset += block_size;
                    } else {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "*** dump is overflowing probable loss of data***");
                        dump_to_scope_ovf = 1;
                    }
                }

                if (dump_to_file) {
                    if (full_mem_alloced != 1) {
                        /* dump this segment to file */
                        file_write(file, n_file_wr_offset, ((unsigned char*)scratch_buf), block_size);
                        n_file_wr_offset += block_size;
                        msleep(100);
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ".");
                    }
                }
                if (full_mem_alloced == 1) {
                    scratch_buf += block_size;
                }
                address += block_size;
                remaining -= block_size;
            }
        }
    }
    if (dump_to_file && full_mem_alloced == 1) {
        /* dump this segment to file */
        file_write(file, n_file_wr_offset, ((unsigned char*)scratch_buf_start), total_mem_length);
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s *** dump collection complete %p %p \n", __func__, file_path, file);

error_1:
    if (dump_to_file && file){
        file_close(file);
    }
    if(dump_to_scope && crash_scope_addr) {
#if !ATH_SUPPORT_FW_RAM_DUMP_FOR_MIPS
        iounmap(crash_scope_addr);
#endif
    }
    if (scratch_buf_start) {
       OS_FREE(scratch_buf_start);
       scratch_buf_start = NULL;
    }
}

int get_next_dump_file_index(struct ol_ath_softc_net80211 *scn, char *fw_dump_file, size_t fw_dump_file_size)
{
    int next_file = 0;

    get_fileindex((char*)&next_file);

    /* get new file name with number ext */
    OS_MEMZERO(fw_dump_file, fw_dump_file_size);

    if (scn->target_type == TARGET_TYPE_AR900B) {
        snprintf(fw_dump_file, fw_dump_file_size, "%s.%d", FW_DUMP_FILE_AR900B, next_file);
    } else if (scn->target_type == TARGET_TYPE_QCA9984) {
        snprintf(fw_dump_file, fw_dump_file_size, "%s.%d", FW_DUMP_FILE_QCA9984, next_file);
    } else if (scn->target_type == TARGET_TYPE_QCA9888) {
        snprintf(fw_dump_file, fw_dump_file_size, "%s.%d", FW_DUMP_FILE_QCA9888, next_file);
    } else if(scn->target_type == TARGET_TYPE_IPQ4019) {
        snprintf(fw_dump_file, fw_dump_file_size, "%s.%d", FW_DUMP_FILE_IPQ4019, next_file);
    } else {
        snprintf(fw_dump_file, fw_dump_file_size, "%s.%d", FW_DUMP_FILE_AR9888, next_file);
    }
    /* next time new number */
    update_fileindex(next_file+1);
    return next_file;
}
atomic_t target_assert_count = ATOMIC_INIT(0);
void ramdump_work_handler(void *scn)
{
    struct ol_ath_softc_net80211 *ramdump_scn = scn;
    char fw_dump_file[128]={0};
    A_UINT32 d_opts ;

    if (!ramdump_scn) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ramdump scn is NULL\n");
        return;
    }
    d_opts = ramdump_scn->sc_dump_opts;
    /* no dump required, just return*/
    if ((d_opts & FW_DUMP_RECOVER_WITHOUT_CORE) &&
            (ramdump_scn->recovery_enable) ) {
        return;
    }

    /* recovery is enabled, but dump is not requested*/
    if (ramdump_scn->recovery_enable &&
            (d_opts & FW_DUMP_RECOVER_WITHOUT_CORE)) {
        return;
    }

	/*
	 * Do not worry now about CrashScope. Dump into file
     */
#if BUILD_X86
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "*** DO NOT CRASH X86, YOU SHOULD UNLOAD DRIVER HERE AFTER *** \n");
    /* for X86 station version, there is no crash scope, and cannot crash */
    d_opts |= FW_DUMP_NO_HOST_CRASH;
    d_opts  &= ~(FW_DUMP_TO_CRASH_SCOPE);
#else
    /* get the next dump file */
    get_next_dump_file_index(scn, fw_dump_file, sizeof(fw_dump_file));
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "** STARTING DUMP options:%x", d_opts);
    fw_get_core_dump(ramdump_scn, fw_dump_file, d_opts);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "*** TARGET ASSERT DUMP COLLECTION COMPLETE ***\n");
#endif
#if UMAC_SUPPORT_ACFG
    OSIF_RADIO_DELIVER_EVENT_WATCHDOG(&(ramdump_scn->sc_ic), ACFG_WDT_FWDUMP_READY);
#endif
    if (!ramdump_scn->recovery_enable && !(d_opts & FW_DUMP_NO_HOST_CRASH)) {
	    if(atomic_dec_and_test(&target_assert_count)) {
		    qdf_target_assert_always(0);
		    /*  this is return of no where, we should ideally wait here */
	    } else {
		    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Do not reboot the board now. There is another target assert in the other radio\n");
	    }
    }
    return;
}
#ifndef REMOVE_INIT_DEBUG_CODE
void ol_ath_dump_u32_buf(uint32_t *ptr, int len);
#endif
void
ol_target_failure(void *instance, QDF_STATUS status)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)instance;
    struct ieee80211com *ic = &scn->sc_ic;
    A_UINT32 reg_dump_area = 0;
    A_UINT32 reg_dump_values[REGISTER_DUMP_LEN_MAX];
    A_UINT32 reg_dump_cnt = 0;
    A_UINT32 i;
    A_UINT32 dbglog_hdr_address;
    struct dbglog_hdr_s dbglog_hdr;
    struct dbglog_buf_s dbglog_buf;
    A_UINT8 *dbglog_data;
    struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)scn->hif_hdl;
    extern int hif_dump_ce_registers(struct hif_opaque_softc *);

    atomic_inc(&target_assert_count);
#ifndef REMOVE_INIT_DEBUG_CODE
     if(scn->nbuf)
     {

         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Recent WMI msg in nbuf - nbuf\n");
         ol_ath_dump_u32_buf((uint32_t*)wbuf_header(scn->nbuf),\
                 wbuf_get_pktlen(scn->nbuf));
         scn->nbuf = NULL;
     } else if(scn->nbuf1) {
         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Recent WMI msg in - nbuf1\n");
         ol_ath_dump_u32_buf((uint32_t*)wbuf_header(scn->nbuf1),\
                 wbuf_get_pktlen(scn->nbuf1));
         scn->nbuf1 = NULL;
     }
#endif

     ic->recovery_in_progress = 1;

#if UMAC_SUPPORT_ACFG
     OSIF_RADIO_DELIVER_EVENT_WATCHDOG(&(scn->sc_ic), ACFG_WDT_TARGET_ASSERT);
#endif

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[%s]: XXX TARGET ASSERTED XXX\n", scn->sc_osdev->netdev->name);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "<< NSS WIFI OFFLOAD INFORMATION >>>\n");

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Radio ID %d with NSS ifnum %d \n",scn->radio_id, scn->nss_ifnum);
#endif
    scn->target_status = OL_TRGET_STATUS_RESET;
    scn->scn_stats.tgt_asserts++;
    if (hif_diag_read_mem(hif_hdl,
                host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_failure_state)),
                (A_UCHAR *)&reg_dump_area,
                sizeof(A_UINT32))!= QDF_STATUS_SUCCESS)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem FW Dump Area Pointer failed\n");
        return;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Target Register Dump Location 0x%08X\n", reg_dump_area);

    if (scn->target_type == TARGET_TYPE_AR6320) {
        reg_dump_cnt = REG_DUMP_COUNT_AR6320;
    } else  if (scn->target_type == TARGET_TYPE_AR9888) {
        reg_dump_cnt = REG_DUMP_COUNT_AR9888;
    } else  if (scn->target_type == TARGET_TYPE_AR900B || scn->target_type == TARGET_TYPE_IPQ4019) {
        reg_dump_cnt = REG_DUMP_COUNT_AR900B;
    } else  if (scn->target_type == TARGET_TYPE_QCA9984) {
        reg_dump_cnt = REG_DUMP_COUNT_QCA9984;
    } else  if (scn->target_type == TARGET_TYPE_QCA9888) {
        reg_dump_cnt = REG_DUMP_COUNT_QCA9888;
    } else {
        A_ASSERT(0);
    }

    if (hif_diag_read_mem(hif_hdl,
                reg_dump_area,
                (A_UCHAR*)&reg_dump_values[0],
                reg_dump_cnt * sizeof(A_UINT32))!= QDF_STATUS_SUCCESS)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem for FW Dump Area failed\n");
        return;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Target Register Dump\n");
    for (i = 0; i < reg_dump_cnt; i++) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[%02d]   :  0x%08X\n", i, reg_dump_values[i]);
    }
    /* initial target dump is over, collect the real dumps now */
    /* Schedule a work queue that resets the radio and
       reload the firmware.
    */
    if (scn->pci_reconnect) {
       QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Resetting  %s radio\n", scn->sc_osdev->netdev->name);
       scn->pci_reconnect(scn);
    }

    //CE Ring Index 2 (0x00057C00 - 0x00057C54)
    //We are interested only in the address region from 0x00057C34.
#if defined(FIXME_AR900B_CRSH_DUMP)
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CE Registers...\n");
    sc = (struct hif_opaque_softc *) scn->hif_hdl;
    if (sc != NULL && sc->mem != NULL) {
        A_UINT32 ce_reg_cnt = 9;
        A_UINT32 ce_reg_start_addr = 0x00057C34;
        A_UINT32 ce_reg_offset = 0;
        A_UINT32 ce_reg_val = 0;
        for (i = 0; i < ce_reg_cnt; i++) {
            ce_reg_val = hif_reg_read(sc, (ce_reg_start_addr + ce_reg_offset));
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[0x%08X]   :  0x%08X\n", (ce_reg_start_addr + ce_reg_offset), ce_reg_val);
            ce_reg_offset += 4;
        }
    }
#endif

    hif_dump_ce_registers((struct hif_opaque_softc *)scn->hif_hdl);

    if (hif_diag_read_mem(hif_hdl,
                host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_dbglog_hdr)),
                (A_UCHAR *)&dbglog_hdr_address,
                sizeof(dbglog_hdr_address))!= QDF_STATUS_SUCCESS)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem FW dbglog_hdr_address failed\n");
        return;
    }

    if (hif_diag_read_mem(hif_hdl,
                dbglog_hdr_address,
                (A_UCHAR *)&dbglog_hdr,
                sizeof(dbglog_hdr))!= QDF_STATUS_SUCCESS)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem FW dbglog_hdr failed\n");
        return;
    }
    if (hif_diag_read_mem(hif_hdl,
                (A_UINT32)dbglog_hdr.dbuf,
                (A_UCHAR *)&dbglog_buf,
                sizeof(dbglog_buf))!= QDF_STATUS_SUCCESS)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem FW dbglog_buf failed\n");
        return;
    }

    if(dbglog_buf.length) {
        dbglog_data = qdf_mem_malloc(dbglog_buf.length + 4);
        if (dbglog_data) {

            if (hif_diag_read_mem(hif_hdl,
                        (A_UINT32)dbglog_buf.buffer,
                        dbglog_data + 4,
                        dbglog_buf.length)!= QDF_STATUS_SUCCESS)
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem FW dbglog_data failed\n");
            } else {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dbglog_hdr.dbuf=%p dbglog_data=%p dbglog_buf.buffer=%p dbglog_buf.length=%u\n",
                        dbglog_hdr.dbuf, dbglog_data, dbglog_buf.buffer, dbglog_buf.length);

                OS_MEMCPY(dbglog_data, &dbglog_hdr.dropped, 4);
                (void)dbglog_parse_debug_logs(scn, dbglog_data, dbglog_buf.length + 4, NULL);
            }
            qdf_mem_free(dbglog_data);
        }
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HifDiagReadiMem FW dbglog_data failed since dbglog_buf.length=%u\n",dbglog_buf.length);
    }
    return;

}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
void ol_notify_if_low_on_buffers(struct ol_ath_softc_net80211 *scn, uint32_t free_buff)
{
    struct ieee80211com *ic = &scn->sc_ic;

    scn->buff_thresh.free_descs = free_buff;
    if(scn->buff_thresh.ald_buffull_wrn &&
            (scn->buff_thresh.free_descs <= scn->buff_thresh.ald_free_buf_lvl)) {
        ieee80211_buffull_handler(ic);
        scn->buff_thresh.ald_buffull_wrn = 0;
    }
}
#endif
/*
 * Routin to lock vap transmit
 *
 */
void ol_vap_tx_lock( void *vosdev)
{
#if !QCA_OL_TX_PDEV_LOCK && QCA_NSS_PLATFORM || (defined QCA_PARTNER_PLATFORM && QCA_PARTNER_SUPPORT_FAST_TX)
    osif_dev  *osdev = (osif_dev  *)vosdev;
    VAP_TX_SPIN_LOCK(&osdev->tx_lock);
#endif
    return;
}

/*
 * Routin to unlock vap transmit
 *
 */
void ol_vap_tx_unlock( void *vosdev)
{
#if !QCA_OL_TX_PDEV_LOCK && QCA_NSS_PLATFORM || (defined QCA_PARTNER_PLATFORM && QCA_PARTNER_SUPPORT_FAST_TX)
    osif_dev  *osdev = (osif_dev  *)vosdev;
    VAP_TX_SPIN_UNLOCK(&osdev->tx_lock);
#endif
    return;
}

#if ATH_DEBUG
extern unsigned long ath_rtscts_enable;
#define MODE_CTS_TO_SELF 0x32
#define MODE_RTS_CTS     0x31
void set_rtscts_enable(osif_dev * osdev)
{
   struct net_device *comdev = osdev->os_comdev;
   struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211*) ath_netdev_priv(comdev);
   wlan_if_t vap = osdev->os_if;

   struct ol_ath_vap_net80211 *avn;
   unsigned int val = ath_rtscts_enable;

   if (vap == NULL) return;

   avn = OL_ATH_VAP_NET80211(vap);

   if (val != scn->rtsctsenable)
   {
     scn->rtsctsenable = val;
     /* Enable CTS-to-self */
     if(val == 1)
         ol_ath_wmi_send_vdev_param( scn,avn->av_if_id,
                     wmi_vdev_param_enable_rtscts, MODE_CTS_TO_SELF);
     /* Enable RTS-CTS */
     else if(val == 2)
         ol_ath_wmi_send_vdev_param( scn,avn->av_if_id,
                     wmi_vdev_param_enable_rtscts, MODE_RTS_CTS);
  }
}
#endif

int
ol_ath_configure_target(struct ol_ath_softc_net80211 *scn)
{
    u_int32_t param;

#if 0
    if (enableuartprint) {
        param = 1;
        if (BMIWriteMemory(ar->arHifDevice,
                           HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_serial_enable),
                           (A_UCHAR *)&param,
                           4)!= A_OK)
        {
             AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIWriteMemory for enableuartprint failed \n"));
             return A_ERROR;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Serial console prints enabled\n"));
    }
#endif

    /* Tell target which HTC version it is used*/
    param = HTC_PROTOCOL_VERSION;
    if (BMIWriteMemory(scn->hif_hdl,
                       host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_app_host_interest)),
                       (u_int8_t *)&param,
                       4, scn)!= A_OK)
    {
         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for htc version failed \n");
         return -1;
    }

#if 0
    if (enabletimerwar) {
        u_int32_t param;

        if (BMIReadMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_option_flag),
            (A_UCHAR *)&param,
            4)!= A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIReadMemory for enabletimerwar failed \n"));
            return A_ERROR;
        }

        param |= HI_OPTION_TIMER_WAR;

        if (BMIWriteMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_option_flag),
            (A_UCHAR *)&param,
            4) != A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIWriteMemory for enabletimerwar failed \n"));
            return A_ERROR;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Timer WAR enabled\n"));
    }
#endif

    /* set the firmware mode to STA/IBSS/AP */
    {
        if (BMIReadMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
            (A_UCHAR *)&param,
            4, scn)!= A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIReadMemory for setting fwmode failed \n");
            return A_ERROR;
        }

    /* TODO following parameters need to be re-visited. */
        param |= (1 << HI_OPTION_NUM_DEV_SHIFT); //num_device
        param |= (HI_OPTION_FW_MODE_AP << HI_OPTION_FW_MODE_SHIFT); //Firmware mode ??
        param |= (1 << HI_OPTION_MAC_ADDR_METHOD_SHIFT); //mac_addr_method
        param |= (0 << HI_OPTION_FW_BRIDGE_SHIFT);  //firmware_bridge
        param |= (0 << HI_OPTION_FW_SUBMODE_SHIFT); //fwsubmode

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"NUM_DEV=%d FWMODE=0x%x FWSUBMODE=0x%x FWBR_BUF %d\n",
                            1, HI_OPTION_FW_MODE_AP, 0, 0);

        if (BMIWriteMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag)),
            (A_UCHAR *)&param,
            4, scn) != A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for setting fwmode failed \n");
            return A_ERROR;
        }
    }

#if (CONFIG_DISABLE_CDC_MAX_PERF_WAR)
    {
        /* set the firmware to disable CDC max perf WAR */
        if (BMIReadMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag2)),
            (A_UCHAR *)&param,
            4, scn)!= A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIReadMemory for setting cdc max perf failed \n");
            return A_ERROR;
        }

        param |= HI_OPTION_DISABLE_CDC_MAX_PERF_WAR;
        if (BMIWriteMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag2)),
            (A_UCHAR *)&param,
            4, scn) != A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for setting cdc max perf failed \n");
            return A_ERROR;
        }
    }
#endif /* CONFIG_CDC_MAX_PERF_WAR */

    /* If host is running on a BE CPU, set the host interest area */
    {
#if defined(BIG_ENDIAN_HOST) && !AH_NEED_TX_DATA_SWAP
        param = 1;
#else
            param = 0;
#endif
        if (BMIWriteMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_be)),
            (A_UCHAR *)&param,
            4, scn) != A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for setting host CPU BE mode failed \n");
            return A_ERROR;
        }
    }

    /* FW descriptor/Data swap flags */
    {
        param = 0;
        if (BMIWriteMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_fw_swap)),
            (A_UCHAR *)&param,
            4, scn) != A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for setting FW data/desc swap flags failed \n");
            return A_ERROR;
        }
    }
    /*Set the TX/RX DATA SWAP mode, if not define any AH_NEED_TX_DATA_SWAP and AH_NEED_RX_DATA_SWAP
	  The vlaue should be zero, that Target will not  enable TX_PACKET_BYTE_SWAP in  MAC_DMA_CFG
	  and PACKET_BYTE_SWAP and HEADER_BYTE_SWAP for MAC_DMA_RCV_RING2_2 */
    {
        param = 0;
#if AH_NEED_TX_DATA_SWAP
        param |= 0x01;
#endif
#if AH_NEED_RX_DATA_SWAP
        param |= 0x02;
#endif
#if ATH_11AC_ACK_POLICY
        param |= 0x04;
#endif
        if (BMIWriteMemory(scn->hif_hdl,
            host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_txrx_dataswap)),
            (A_UCHAR *)&param,
            4, scn) != A_OK)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for setting host TX/RX SWAP mode failed \n");
            return A_ERROR;
        }
    }

#if 0
#ifdef ATH6KL_DISABLE_TARGET_DBGLOGS
    {
        u_int32_t param;

        if (BMIReadMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_option_flag),
            (A_UCHAR *)&param,
            4)!= A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIReadMemory for disabling debug logs failed\n"));
            return A_ERROR;
        }

        param |= HI_OPTION_DISABLE_DBGLOG;

        if (BMIWriteMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_option_flag),
            (A_UCHAR *)&param,
            4) != A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIWriteMemory for HI_OPTION_DISABLE_DBGLOG\n"));
            return A_ERROR;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Firmware mode set\n"));
    }
#endif /* ATH6KL_DISABLE_TARGET_DBGLOGS */

    if (regscanmode) {
        u_int32_t param;

        if (BMIReadMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_option_flag),
            (A_UCHAR *)&param,
            4)!= A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIReadMemory for setting regscanmode failed\n"));
            return A_ERROR;
        }

        if (regscanmode == 1) {
            param |= HI_OPTION_SKIP_REG_SCAN;
        } else if (regscanmode == 2) {
            param |= HI_OPTION_INIT_REG_SCAN;
        }

        if (BMIWriteMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_option_flag),
            (A_UCHAR *)&param,
            4) != A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIWriteMemory for setting regscanmode failed\n"));
            return A_ERROR;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Regulatory scan mode set\n"));
    }

#if defined(AR6003_REV2_BOARD_EXT_DATA_ADDRESS)
    /*
     * Hardcode the address use for the extended board data
     * Ideally this should be pre-allocate by the OS at boot time
     * But since it is a new feature and board data is loaded
     * at init time, we have to workaround this from host.
     * It is difficult to patch the firmware boot code,
     * but possible in theory.
     */
    if (ar->arTargetType == TARGET_TYPE_AR6003) {
        u_int32_t ramReservedSz;
        if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
            param = AR6003_REV2_BOARD_EXT_DATA_ADDRESS;
            ramReservedSz =  AR6003_REV2_RAM_RESERVE_SIZE;
        } else {
            param = AR6003_REV3_BOARD_EXT_DATA_ADDRESS;
            ramReservedSz =  AR6003_REV3_RAM_RESERVE_SIZE;
        }
        if (BMIWriteMemory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_board_ext_data),
            (A_UCHAR *)&param,
            4) != A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIWriteMemory for hi_board_ext_data failed \n"));
            return A_ERROR;
        }
        if (BMIWriteMemory(ar->arHifDevice,
              HOST_INTEREST_ITEM_ADDRESS(ar->arTargetType, hi_end_RAM_reserve_sz),
              (A_UCHAR *)&ramReservedSz, 4) != A_OK)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("BMIWriteMemory for hi_end_RAM_reserve_sz failed \n"));
            return A_ERROR;
        }
    }
#endif /* AR6003_REV2_BOARD_EXT_DATA_ADDRESS */
    /* For AR6004: Size reserved at the end of RAM is done by wlansetup app */

        /* since BMIInit is called in the driver layer, we have to set the block
         * size here for the target */

    if (A_FAILED(ar6000_set_htc_params(ar->arHifDevice,
                                       ar->arTargetType,
                                       mbox_yield_limit,
                                       0 /* use default number of control buffers */
                                       ))) {
        return A_ERROR;
    }

    if (setupbtdev != 0) {
        if (A_FAILED(ar6000_set_hci_bridge_flags(ar->arHifDevice,
                                                 ar->arTargetType,
                                                 setupbtdev))) {
            return A_ERROR;
        }
    }
#endif
    return A_OK;
}

int
ol_check_dataset_patch(struct ol_ath_softc_net80211 *scn, u_int32_t *address)
{
    /* Check if patch file needed for this target type/version. */
    return 0;
}


#ifdef HIF_SDIO
static A_STATUS
ol_sdio_extra_initialization(struct ol_ath_softc_net80211 *scn)
{
    A_STATUS status;
    do{
        A_UINT32 blocksizes[HTC_MAILBOX_NUM_MAX];
        unsigned int MboxIsrYieldValue = 99;
        A_UINT32 TargetType = TARGET_TYPE_AR6320;
        /* get the block sizes */
        status = HIFConfigureDevice(scn->hif_hdl, HIF_DEVICE_GET_MBOX_BLOCK_SIZE,
                                    blocksizes, sizeof(blocksizes));

        if (A_FAILED(status)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to get block size info from HIF layer...\n");
            break;
        }else{
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "get block size info from HIF layer:%x,%x,%x,%x\n",
                    blocksizes[0], blocksizes[1], blocksizes[2], blocksizes[3]);
        }
            /* note: we actually get the block size for mailbox 1, for SDIO the block
             * size on mailbox 0 is artificially set to 1 */
            /* must be a power of 2 */
        A_ASSERT((blocksizes[1] & (blocksizes[1] - 1)) == 0);

            /* set the host interest area for the block size */
        status = BMIWriteMemory(scn->hif_hdl,
                                HOST_INTEREST_ITEM_ADDRESS(TargetType, hi_mbox_io_block_sz),
                                (A_UCHAR *)&blocksizes[1],
                                4,
                                scn);

        if (A_FAILED(status)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for IO block size failed \n");
            break;
        }else{
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for IO block size succeeded \n");
        }

        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Block Size Set: %d (target address:0x%X)\n",
                blocksizes[1], HOST_INTEREST_ITEM_ADDRESS(TargetType, hi_mbox_io_block_sz));

        if (MboxIsrYieldValue != 0) {
                /* set the host interest area for the mbox ISR yield limit */
            status = BMIWriteMemory(scn->hif_hdl,
                                    HOST_INTEREST_ITEM_ADDRESS(TargetType, hi_mbox_isr_yield_limit),
                                    (A_UCHAR *)&MboxIsrYieldValue,
                                    4,
                                    scn);

            if (A_FAILED(status)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "BMIWriteMemory for yield limit failed \n");
                break;
            }
        }
    }while(FALSE);
    return status;
}
#endif


#ifdef CONFIG_AR900B_SUPPORT
int
ol_get_board_id(struct ol_ath_softc_net80211 *scn, char *boarddata_file )
{
    char *filebuf = NULL;
    int buflen = 0;
    filebuf = qdf_mem_malloc(MAX_FILENAMES_SIZE);
    if(!filebuf) {
        qdf_print("\n %s : Alloc failed\n",__FUNCTION__);
        return -1;
    }
    /* For besra,there is NO number of boardfiles like cascade.*/
    if ((scn->target_type == TARGET_TYPE_QCA9984 && emu_type != 0) || (scn->target_type == TARGET_TYPE_IPQ4019) || \
                (scn->target_type == TARGET_TYPE_QCA9888)) {
        qdf_mem_set(filebuf, sizeof(filebuf), 0);
    } else {
        buflen = get_filenames(scn->target_type,(char*)filebuf, MAX_FILENAMES_SIZE);
        if (buflen <= 0) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Failed to read board data file list!\n", __func__);
            qdf_mem_free(filebuf);
            return -1;
        }
    }
    if (boardid_to_filename(scn, board_id, filebuf, buflen, boarddata_file) != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Failed to determine board data file name!\n", __func__);
        qdf_mem_free(filebuf);
#if DEFAULT_BOARD_DATA
         /* Made change in boardid_to_filename to fall back to default boarddata file since few boards have Invalid boardID 0 */
        return 0;
#else
        return -1;
#endif
    }
   qdf_mem_free(filebuf);
   return 0;
}
EXPORT_SYMBOL(ol_get_board_id);
#endif

#if ATH_SUPPORT_CODESWAP
static
int ol_derive_swap_filename (const char* bin_filename, char* swap_filename, ATH_SWAP_INFO file) {

    char temp[MAX_SWAP_FILENAME], *split_name;
    const char* filename = bin_filename;
    int len =0, dot_count=0, tot_dotcount=0;

    split_name = &temp[0];

    if(!bin_filename) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Bin file not present\n",__func__);
        return -1;
    }

    while (*filename) {
        if(*filename == '.')
            tot_dotcount++;
        filename++;
    }

    filename = bin_filename;

    while (*filename && len < MAX_SWAP_FILENAME) {
        if(*filename == '.')
            dot_count++;
        *split_name++ = *filename++;
        len++;
        if(dot_count == tot_dotcount)
            break;
    }

    if (len == MAX_SWAP_FILENAME)
        *(--split_name) = '\0';
    else
        *split_name = '\0';

    split_name = temp;

    switch (file) {

    case ATH_TARGET_OTP_CODE_SWAP:
    case ATH_TARGET_BIN_UTF_CODE_SWAP:
    case ATH_TARGET_BIN_CODE_SWAP:
           strlcat(split_name, TARGET_CODE_SWAP_FILE_EXT_TYPE, MAX_SWAP_FILENAME);
           break;
    case ATH_TARGET_BIN_DATA_SWAP:
    case ATH_TARGET_OTP_DATA_SWAP:
    case ATH_TARGET_BIN_UTF_DATA_SWAP:
           strlcat(split_name, TARGET_DATA_SWAP_FILE_EXT_TYPE, MAX_SWAP_FILENAME);
           break;

    default:
          break;

    }

   memcpy(swap_filename,split_name,strlen(split_name));
   return 1;
}


int
ol_transfer_swap_struct(struct ol_ath_softc_net80211 *scn, ATH_SWAP_INFO swap_info,char *bin_filename) {

    struct hif_opaque_softc *sc = (struct hif_opaque_softc *)scn->hif_hdl;
    struct swap_seg_info *seg_info;
    const char *file_name = bin_filename;
    A_STATUS rv;
    u_int32_t target_write_addr;
    u_int64_t *cpu_addr;
    int status = -1;

    if (!sc) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: hif_pci_softc is null\n", __func__);
        return status;
    }

    switch (swap_info) {

        case ATH_TARGET_OTP_CODE_SWAP:
            /*check for previous swap seg alloc*/
            if(!scn->target_otp_codeswap_seginfo) {
                /* Allocate swap seg  */
                status = ol_swap_seg_alloc (scn, &seg_info, &cpu_addr, file_name, swap_info);
                /*successfull swap seg alloc*/
                if (status == 0) {
                    scn->target_otp_codeswap_seginfo = seg_info;
                    scn->target_otp_codeswap_cpuaddr = cpu_addr;
                }
            } else {
                /* reuse the previously allocated swap seg info */
                seg_info = scn->target_otp_codeswap_seginfo;
                status = 0;
            }
            break;

        case ATH_TARGET_OTP_DATA_SWAP:
            /*check for previous swap seg alloc*/
            if(!scn->target_otp_dataswap_seginfo) {
                /* Allocate swap seg  */
                status = ol_swap_seg_alloc (scn, &seg_info, &cpu_addr, file_name, swap_info);
                /*successfull swap seg alloc*/
                if (status == 0) {
                    scn->target_otp_dataswap_seginfo = seg_info;
                    scn->target_otp_dataswap_cpuaddr = cpu_addr;
                }
            } else {
                /* reuse the previously allocated swap seg info */
                seg_info = scn->target_otp_dataswap_seginfo;
                status = 0;
            }
            break;

        case ATH_TARGET_BIN_CODE_SWAP:
            /*check for previous swap seg alloc*/
            if(!scn->target_bin_codeswap_seginfo) {
                /* Allocate swap seg  */
                status = ol_swap_seg_alloc (scn, &seg_info, &cpu_addr, file_name, swap_info);
                /*successfull swap seg alloc*/
                if (status == 0) {
                    scn->target_bin_codeswap_seginfo = seg_info;
                    scn->target_bin_codeswap_cpuaddr = cpu_addr;
                }
            } else {
                /* reuse the previously allocated swap seg info */
                seg_info = scn->target_bin_codeswap_seginfo;
                status = 0;
            }
            break;

        case ATH_TARGET_BIN_DATA_SWAP:
            /*check for previous swap seg alloc*/
            if(!scn->target_bin_dataswap_seginfo) {
                /* Allocate swap seg  */
                status = ol_swap_seg_alloc (scn, &seg_info, &cpu_addr, file_name, swap_info);
                /*successfull swap seg alloc*/
                if (status == 0) {
                    scn->target_bin_dataswap_seginfo = seg_info;
                    scn->target_bin_dataswap_cpuaddr = cpu_addr;
                }
            } else {
                /* reuse the previously allocated swap seg info */
                seg_info = scn->target_bin_dataswap_seginfo;
                status = 0;
            }
            break;

        case ATH_TARGET_BIN_UTF_CODE_SWAP:
            /*check for previous swap seg alloc*/
            if(!scn->target_bin_utf_codeswap_seginfo) {
                /* Allocate swap seg  */
                status = ol_swap_seg_alloc (scn, &seg_info, &cpu_addr, file_name, swap_info);
                /*successfull swap seg alloc*/
                if (status == 0) {
                    scn->target_bin_utf_codeswap_seginfo = seg_info;
                    scn->target_bin_utf_codeswap_cpuaddr = cpu_addr;
                }
            } else {
                /* reuse the previously allocated swap seg info */
                seg_info = scn->target_bin_utf_codeswap_seginfo;
                status = 0;
            }
            break;

        case ATH_TARGET_BIN_UTF_DATA_SWAP:
            /*check for previous swap seg alloc*/
            if(!scn->target_bin_utf_dataswap_seginfo) {
                /* Allocate swap seg  */
                status = ol_swap_seg_alloc (scn, &seg_info, &cpu_addr, file_name, swap_info);
                /*successfull swap seg alloc*/
                if (status == 0) {
                    scn->target_bin_utf_dataswap_seginfo = seg_info;
                    scn->target_bin_utf_dataswap_cpuaddr = cpu_addr;
                }
            } else {
                /* reuse the previously allocated swap seg info */
                seg_info = scn->target_bin_utf_dataswap_seginfo;
                status = 0;
            }
            break;

        default :
            break;

    }

    if (status !=0 ) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Swap Seg alloc failed for FW bin type %d \n",__func__,swap_info);
        return status;
    }

    /* Parse the code/data swap file and copy to the host memory & get target write addr */
    if (ol_swap_wlan_memory_expansion(scn,seg_info,file_name,&target_write_addr)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Swap Memory expansion failed for FW bin type %d \n",__func__,swap_info);
        status = -1;
        return status;
    }

    /* Write the code/data seg info to the target addr  obtained above memory expansion*/
    rv  = BMIWriteMemory(scn->hif_hdl, target_write_addr,
            (u_int8_t *)seg_info, sizeof(struct swap_seg_info), scn);

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"scn=%p  target_write_addr=%x seg_info=%p \n", scn,target_write_addr,(u_int8_t *)seg_info);

    if (rv != A_OK) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to Write for Target Memory Expansion target_addr=%x \n",target_write_addr);
        return rv;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s:Code swap structure successfully downloaded for bin type =%d \n",__func__,swap_info);
    return 0;
}


int
ol_ath_code_data_swap(struct ol_ath_softc_net80211 *scn,const char * bin_filename, ATH_BIN_FILE file_type) {

    char swap_filename[FILE_PATH_LEN];
    char filepath [FILE_PATH_LEN];
    const char *filename_path = filepath;
    struct file *file;
    int status =0;
    int code_swap_type, data_swap_type;

    if(!bin_filename)
        return status;

    switch (file_type) {

        case ATH_OTP_FILE:
            code_swap_type = ATH_TARGET_OTP_CODE_SWAP;
            data_swap_type = ATH_TARGET_OTP_DATA_SWAP;
            break;
        case ATH_FIRMWARE_FILE:
            code_swap_type = ATH_TARGET_BIN_CODE_SWAP;
            data_swap_type = ATH_TARGET_BIN_DATA_SWAP;
            break;
        case ATH_UTF_FIRMWARE_FILE:
            code_swap_type = ATH_TARGET_BIN_UTF_CODE_SWAP;
            data_swap_type = ATH_TARGET_BIN_UTF_DATA_SWAP;
            break;
        default:
            return status;
    }

    memset(&swap_filename[0], 0, sizeof(swap_filename));
    ol_derive_swap_filename(bin_filename, swap_filename, code_swap_type);

    memset(&filepath[0], 0, sizeof(filepath));
    strlcpy(filepath, SWAP_FILE_PATH, sizeof(filepath));
    if (strlcat(filepath, swap_filename, sizeof(filepath)) >= sizeof(filepath))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d file path len exceeds array len",__func__,__LINE__);
        return -ENAMETOOLONG;
    }

    /* Target OTP  Code Swap & Data swap should always happen
     * before downloading the actual OTP binary  file  */
    file = file_open(filename_path, O_RDONLY, 00644);
    if (file) {
        file_close(file);
        /* Allocate, expand & write otp code swap address to fw */
        status = ol_transfer_swap_struct(scn, code_swap_type, swap_filename);
        if(status != 0) {
            return status;
        }
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "bin_filename=%s swap_filename=%s \n",bin_filename, filepath);
    }

    memset(&swap_filename[0], 0, sizeof(swap_filename));
    ol_derive_swap_filename(bin_filename, swap_filename, data_swap_type);

    memset(&filepath[0], 0, sizeof(filepath));
    strlcpy(filepath, SWAP_FILE_PATH, sizeof(filepath));
    if (strlcat(filepath, swap_filename, sizeof(filepath)) >= sizeof(filepath))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d file path len exceeds array len",__func__,__LINE__);
        return -ENAMETOOLONG;
    }

    file = file_open(filename_path, O_RDONLY, 00644);
    if (file) {
        file_close(file);
        /* Allocate, expand & write otp code swap address to fw */
        status = ol_transfer_swap_struct(scn, data_swap_type, swap_filename);
        if(status != 0) {
            return status;
        }
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "bin_filename=%s swap_filename=%s \n",bin_filename, filepath);
    }
    return status;
}
#endif

static inline int
ol_download_cal_data (struct ol_ath_softc_net80211   *scn,
                      u_int32_t address, bool compressed)
{
    int status = -EINVAL;
    int file = -EINVAL;

#ifdef AH_CAL_IN_FILE_HOST
        if ( scn->cal_in_file )
#else
        if ( scn->cal_in_flash )
#endif
    {
        /*
         * FLASH has highest priority so try to download it first.
         */
        status = ol_transfer_bin_file(scn, ATH_FLASH_FILE, address, FALSE);
        file = ATH_FLASH_FILE;
    }
    if (status) {
        /*
         * EEPROM has second highest priority so try to download it now.
         */
        status = ol_transfer_target_eeprom_caldata(scn, address, FALSE);
        file = ATH_TARGET_EEPROM_FILE;
        if (status) {
            /*
             * Board data has least priority so try to download it now.
             */
            status = ol_transfer_bin_file(scn, ATH_BOARD_DATA_FILE, address, FALSE);
            file = ATH_BOARD_DATA_FILE;
        }
    }
    if (status) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board data download failed, download address: %p\n",
                 __func__, (void *)address);
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Board data file: %d successfully downloaded, download address: %p\n",
                 __func__, file, (void *)address);
    }
    return status;
}

    static int
ol_validate_otp_mod_param(uint32_t param)
{

    /* Note this sanity checks only module param given or not
     * Its user responsibility to properly feed
     * module param. This is intentionally done.
     */
    if(param == 0xffffffff)
        return -1;

    return 0;
}

int
ol_ath_download_firmware(struct ol_ath_softc_net80211 *scn)
{
    u_int32_t param = 0, address = 0, flash_download_fail = 0;
    int status = !EOK;
    int phase = 0 ;
    struct ieee80211com *ic = &scn->sc_ic;

    if (scn->device_id != AR9887_DEVICE_ID && scn->target_type != TARGET_TYPE_AR9888) {
#ifdef AH_CAL_IN_FILE_HOST
        if( scn->cal_in_file )
#else
        if( scn->cal_in_flash )
#endif
        {
            /* Transfer Board Data from Target EEPROM to Target RAM */
            /* Determine where in Target RAM to write Board Data */
            if (scn->target_version != AR6004_VERSION_REV1_3) {
                BMIReadMemory(scn->hif_hdl,
                        host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_board_data)),
                        (u_int8_t *)&address, 4, scn);
            }

            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Target Version is %x\n",scn->target_version);
            if (!address) {
                if (scn->target_version == AR6004_REV1_VERSION)  {
                    address = AR6004_REV1_BOARD_DATA_ADDRESS;
                } else if (scn->target_version == AR6004_VERSION_REV1_3) {
                    address = AR6004_REV5_BOARD_DATA_ADDRESS;
                }
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Target address not known! Using 0x%x\n", __func__, address);
            }
            /* Write EEPROM or Flash data to Target RAM */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Flash Download Address  %x \n",address);
            status = ol_transfer_bin_file(scn, ATH_FLASH_FILE, address, FALSE);
            if(status != EOK) {
                flash_download_fail = 1;
            }

            /* Record the fact that Board Data is initialized */
            if ((!flash_download_fail) && (scn->target_version != AR6004_VERSION_REV1_3)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Board data initialized\n");
                param = 1;
                BMIWriteMemory(scn->hif_hdl,
                        host_interest_item_address(scn->target_type,
                            offsetof(struct host_interest_s, hi_board_data_initialized)),
                        (u_int8_t *)&param, 4, scn);
            }
        } /*flash mode */

        if (ic->recovery_in_progress == 0 || scn->target_type == TARGET_TYPE_IPQ4019)
        {
            /*
             * Download first otp bin to get a board id
             */
            /* Transfer One Time Programmable data */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: Download OTP, flash download ADDRESS 0x%x\n",__func__,address);
            address = BMI_SEGMENTED_WRITE_ADDR;
#if defined(ATH_CONFIG_FW_SIGN)
            status = ol_transfer_bin_file(scn, ATH_OTP_FILE, address, FALSE);
#else
            status = ol_transfer_bin_file(scn, ATH_OTP_FILE, address, TRUE);
#endif
            if (status == EOK) {
                /* Execute the OTP code only if entry found and downloaded */
                /* FLASH MODE and FILE MODE ONLY */
#ifdef AH_CAL_IN_FILE_HOST
                if ( scn->cal_in_file )
#else
                if ( scn->cal_in_flash )
#endif
                {
                if(flash_download_fail) {
                    param = PARAM_EEPROM_SECTION_MAC; /* Get MAC address only from Eeprom */
                }
                else {
                    param = PARAM_GET_BID_FROM_FLASH; /* Get BoardID first */
                }
                }// scn->cal_in_flash and scn->cal_in_file
            else {
                param = PARAM_GET_CHIPVER_BID; /* Get BoardID first */
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"\n First OTP send param %x\n", param);
            if((status = BMIExecute(scn->hif_hdl, address, &param, scn, 1))!= A_OK ) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : OTP download and Execute failed . status :%d  \n",__func__,status);
                phase = 2 ;
                goto failed;
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s :First OTP download and Execute is good address:0x%x return param %d\n",__func__, param,address);
            } else if ( status == -1 ) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : ol_transfer_bin_file failed. status :%d \n",__func__,status);
                return status ;
            }

#ifdef CONFIG_AR900B_SUPPORT
#define RET_BOARDID_LSB      10
#define RET_BOARDID_MASK     0x1f
        board_id = (param >> RET_BOARDID_LSB) & RET_BOARDID_MASK;
        scn->board_id = board_id;
        if(
#ifdef AH_CAL_IN_FILE_HOST
        scn->cal_in_file &&
#endif
        flash_download_fail) {
            board_id = 0;
        }
#define RET_CHIPID_LSB      15
#define RET_CHIPID_MASK     0x03
        chipid = (param >> RET_CHIPID_LSB) & RET_CHIPID_MASK;
        scn->chipid = chipid;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:##Board Id %d , CHIP Id %d\n",__func__,board_id, chipid);
#endif

        } else {
            /* FW Recovery in progress, use the already stored board id */
#ifdef CONFIG_AR900B_SUPPORT
            board_id = scn->board_id;
            if(
#ifdef AH_CAL_IN_FILE_HOST
               scn->cal_in_file &&
#endif
               flash_download_fail) {
                board_id = 0;
            }
            chipid = scn->chipid;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                           "%s:##Recovered Board Id %d , CHIP Id %d\n",__func__,board_id, chipid);
#endif
        }
    }

    /* Transfer Board Data from Target EEPROM to Target RAM */
    /* Determine where in Target RAM to write Board Data */
    if (scn->target_version != AR6004_VERSION_REV1_3) {
         BMIReadMemory(scn->hif_hdl,
         host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_board_data)),
                                   (u_int8_t *)&address, 4, scn);
    }

    if (!address) {
         if (scn->target_version == AR6004_REV1_VERSION)  {
             address = AR6004_REV1_BOARD_DATA_ADDRESS;
         } else if (scn->target_version == AR6004_VERSION_REV1_3) {
              address = AR6004_REV5_BOARD_DATA_ADDRESS;
         }
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Target address not known! Using 0x%x\n", __func__, address);
    }

    if(scn->device_id == AR9887_DEVICE_ID) {
         status = ol_download_cal_data(scn, address, FALSE);
    } else if ( scn->device_id == AR9888_DEVICE_ID ) {
#ifdef AH_CAL_IN_FILE_HOST
        if ( scn->cal_in_file )
#else
        if ( scn->cal_in_flash )
#endif
        {
            /* Write EEPROM or Flash data to Target RAM */
            status = ol_transfer_bin_file(scn, ATH_FLASH_FILE, address, FALSE);
        }
    }

    if (!scn->is_ar900b) {
        param = 0;
        board_id = 1;
    }

    if ((status == EOK && param == 0) && (board_id !=0 )) {
        /* Record the fact that Board Data is initialized */
        if (scn->target_version != AR6004_VERSION_REV1_3) {
            param = 1;
            BMIWriteMemory(scn->hif_hdl,
                           host_interest_item_address(scn->target_type,
                               offsetof(struct host_interest_s, hi_board_data_initialized)),
                           (u_int8_t *)&param, 4, scn);
        }
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: BOARDDATA DOWNLOAD TO address 0x%x\n",__func__, address);
        /* Flash is either not available or invalid */
        if (ol_transfer_bin_file(scn, ATH_BOARD_DATA_FILE, address, FALSE) != EOK) {
            phase = 1 ;
            goto failed;
        }

        /* Record the fact that Board Data is initialized */
        if (scn->target_version != AR6004_VERSION_REV1_3) {
            param = 1;
            BMIWriteMemory(scn->hif_hdl,
                           host_interest_item_address(scn->target_type,
                               offsetof(struct host_interest_s, hi_board_data_initialized)),
                           (u_int8_t *)&param, 4, scn);
        }

        /* Transfer One Time Programmable data */
        address = BMI_SEGMENTED_WRITE_ADDR;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: Using 0x%x for the remainder of init\n", __func__, address);
#if defined(ATH_CONFIG_FW_SIGN)
        status = ol_transfer_bin_file(scn, ATH_OTP_FILE, address, FALSE);
#else
        status = ol_transfer_bin_file(scn, ATH_OTP_FILE, address, TRUE);
#endif
        if (status == EOK) {
            /* Execute the OTP code only if entry found and downloaded */
#ifdef AH_CAL_IN_FILE_HOST
            if ( scn->cal_in_file )
#else
            if ( scn->cal_in_flash )
#endif
            {
                if(flash_download_fail) {
                    param = PARAM_EEPROM_SECTION_MAC; /* Get MAC address only from Eeprom */
                }
                else {
                    if(ol_validate_otp_mod_param(otp_mod_param) < 0) {
                        qdf_print("\n [Flash] : Ignore Module param\n");
                        param = PARAM_FLASH_SECTION_ALL;
                    }
                    else{
                        param = otp_mod_param;
                        qdf_print("\n [Flash] : Module param 0x%x selected\n", otp_mod_param);
                    }
                }
            } // scn->cal_in_flash and scn->cal_in_file
            else {
                if(ol_validate_otp_mod_param(otp_mod_param) < 0) {
                    qdf_print(KERN_INFO"\n [Non-Flash] : Ignore Module param\n");
                    param = PARAM_EEPROM_SECTION_MAC | PARAM_EEPROM_SECTION_REGDMN | PARAM_EEPROM_SECTION_CAL;
                }
                else {
                    param = otp_mod_param;
                    qdf_print("\n [Non-Flash] mode :  Module param 0x%x selected\n", otp_mod_param);
                }
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"\n Second otp download Param %x \n", param);
            if((status = BMIExecute(scn->hif_hdl, address, &param, scn, 1))!= A_OK ) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : OTP download and Execute failed . status :%d  \n",__func__,status);
                phase = 2 ;
                goto failed;
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Second OTP download and Execute is good, param=0x%x \n",__func__,param);
        } else if ( status == -1 ) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : ol_transfer_bin_file failed. status :%d \n",__func__,status);
            return status ;
        }
    }

    /* Bypass PLL setting */
    if (scn->target_version == AR9888_REV2_VERSION || scn->target_version == AR9887_REV1_VERSION) {
        param = 1;
        BMIWriteMemory(scn->hif_hdl,host_interest_item_address(scn->target_type,
                        offsetof(struct host_interest_s, hi_skip_clock_init)),(u_int8_t *)&param, 4, scn);
    }

    /* Download Target firmware - TODO point to target specific files in runtime */
    address = BMI_SEGMENTED_WRITE_ADDR;
#if defined(ATH_CONFIG_FW_SIGN)
    if(ol_transfer_bin_file(scn, ATH_FIRMWARE_FILE, address, FALSE) != EOK) {
#else
    if (ol_transfer_bin_file(scn, ATH_FIRMWARE_FILE, address, TRUE) != EOK) {
#endif
            phase = 3 ;
            goto failed;
    }

    /* Apply the patches */
    if (ol_check_dataset_patch(scn, &address))
    {
        if ((ol_transfer_bin_file(scn, ATH_PATCH_FILE, address, FALSE)) != EOK) {
            phase = 4 ;
            goto failed;
        }
        BMIWriteMemory(scn->hif_hdl,
                     host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_dset_list_head)),
                     (u_int8_t *)&address, 4, scn);
    }

    if (scn->enableuartprint) {
        /* Configure GPIO AR9888 UART */
        if (scn->target_version == AR6004_VERSION_REV1_3) {
            param = 15;
        } else {
            param = 7;
        }
        BMIWriteMemory(scn->hif_hdl,
                host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_dbg_uart_txpin)),
                (u_int8_t *)&param, 4, scn);
        param = 1;
        BMIWriteMemory(scn->hif_hdl,
                host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_serial_enable)),
                (u_int8_t *)&param, 4, scn);

        /* band rates is 19200 for AR9888v2 */
        if (scn->target_version == AR9888_REV2_VERSION || scn->target_version == AR9887_REV1_VERSION) {
            param = 19200;
            BMIWriteMemory(scn->hif_hdl,
                    host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_desired_baud_rate)),
                    (u_int8_t *)&param, 4, scn);
        }
    }else {
        /*
         * Explicitly setting UART prints to zero as target turns it on
         * based on scratch registers.
         */
        param = 0;
        BMIWriteMemory(scn->hif_hdl,
                host_interest_item_address(scn->target_type, offsetof(struct host_interest_s,hi_serial_enable)),
                (u_int8_t *)&param, 4, scn);
    }

    if (allocram_track_max > 0) {
        param = allocram_track_max;
        BMIWriteMemory(scn->hif_hdl,
                host_interest_item_address(scn->target_type,
                    offsetof(struct host_interest_s, hi_allocram_track_max)),
                    (u_int8_t *)&param, 4, scn);
    }
    if (scn->target_version == AR6004_VERSION_REV1_3) {
        A_UINT32 blocksizes[HTC_MAILBOX_NUM_MAX] = {0x10,0x10,0x10,0x10};
        BMIWriteMemory(scn->hif_hdl,
                host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_mbox_io_block_sz)),
                 (A_UCHAR *)&blocksizes[1], 4, scn);
    }
#ifdef HIF_SDIO
    return ol_sdio_extra_initialization(scn);
#else
    /* Must initialize as for wifi1 it still carries prev values */
    board_id = 0;
    return EOK;
#endif

failed:
       QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : ol_transfer_bin_file failed. phase:%d \n",__func__,phase);
       return -1 ;
}

int
ol_ath_set_host_app_area(struct ol_ath_softc_net80211 *scn)
{
//    printk("ol_ath_set_host_app_area TODO\n");
#if 0
    u_int32_t address, data;
    struct host_app_area_s host_app_area;

    /* Fetch the address of the host_app_area_s instance in the host interest area */
    address = TARG_VTOP(scn->target_type, HOST_INTEREST_ITEM_ADDRESS(scn->target_type, hi_app_host_interest));
    if (ar6000_ReadRegDiag(scn->hif_hdl, &address, &data) != A_OK) {
        return A_ERROR;
    }
    address = TARG_VTOP(scn->target_type, data);
    host_app_area.wmi_protocol_ver = WMI_PROTOCOL_VERSION;
    if (ar6000_WriteDataDiag(scn->hif_hdl, address,
                             (A_UCHAR *)&host_app_area,
                             sizeof(struct host_app_area_s)) != A_OK)
    {
        return A_ERROR;
    }
#endif
    return A_OK;
}
A_STATUS HIF_USB_connect_service(struct ol_ath_softc_net80211 *scn)
{
    int status;
    HTC_SERVICE_CONNECT_REQ connect;
    HTC_SERVICE_CONNECT_RESP response;
    A_MEMZERO(&connect,sizeof(connect));

    connect.EpCallbacks.EpSendFull        = NULL;
    connect.EpCallbacks.EpRecv            = NULL;
    connect.LocalConnectionFlags |= HTC_LOCAL_CONN_FLAGS_ENABLE_SEND_BUNDLE_PADDING;
    connect.MaxSendMsgSize =  1664;
    connect.service_id = WMI_DATA_BE_SVC;
    if ((status = htc_connect_service(scn->htc_handle, &connect, &response))
            != EOK) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to connect to Endpoint Ping BE service status:%d \n", status);
        return -1;;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "eppingtest BE endpoint:%d\n", response.Endpoint);
    }
    connect.service_id= WMI_DATA_BK_SVC;
    if ((status = htc_connect_service(scn->htc_handle, &connect, &response))
            != EOK) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to connect to Endpoint Ping BK service status:%d \n", status);
        return -1;;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "eppingtest BK endpoint:%d\n", response.Endpoint);
    }
    connect.service_id = WMI_DATA_VI_SVC;
    if ((status = htc_connect_service(scn->htc_handle, &connect, &response))
            != EOK) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to connect to Endpoint Ping VI service status:%d \n", status);
        return -1;;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "eppingtest VI endpoint:%d\n", response.Endpoint);
    }
    connect.service_id = WMI_DATA_VO_SVC;
    if ((status = htc_connect_service(scn->htc_handle, &connect, &response))
            != EOK) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Failed to connect to Endpoint Ping VO service status:%d \n", status);
        return -1;;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "eppingtest VO endpoint:%d\n", response.Endpoint);
    }
    return EOK;
}
int
ol_ath_connect_htc(struct ol_ath_softc_net80211 *scn)
{
    int status;
    HTC_SERVICE_CONNECT_REQ connect;

    OS_MEMZERO(&connect,sizeof(connect));

    /* meta data is unused for now */
    connect.pMetaData = NULL;
    connect.MetaDataLength = 0;
    /* these fields are the same for all service endpoints */
    connect.EpCallbacks.pContext = scn;
    connect.EpCallbacks.EpTxCompleteMultiple = NULL /* Control path completion ar6000_tx_complete */;
    connect.EpCallbacks.EpRecv = NULL /* Control path rx */;
    connect.EpCallbacks.EpRecvRefill = NULL /* ar6000_rx_refill */;
    connect.EpCallbacks.EpSendFull = NULL /* ar6000_tx_queue_full */;
#if 0
    /* set the max queue depth so that our ar6000_tx_queue_full handler gets called.
     * Linux has the peculiarity of not providing flow control between the
     * NIC and the network stack. There is no API to indicate that a TX packet
     * was sent which could provide some back pressure to the network stack.
     * Under linux you would have to wait till the network stack consumed all sk_buffs
     * before any back-flow kicked in. Which isn't very friendly.
     * So we have to manage this ourselves */
    connect.MaxSendQueueDepth = MAX_DEFAULT_SEND_QUEUE_DEPTH;
    connect.EpCallbacks.RecvRefillWaterMark = AR6000_MAX_RX_BUFFERS / 4; /* set to 25 % */
    if (0 == connect.EpCallbacks.RecvRefillWaterMark) {
        connect.EpCallbacks.RecvRefillWaterMark++;
    }
#endif
#if 0
    /* connect to control service */
    connect.ServiceID = WMI_CONTROL_SVC;
    if ((status = ol_ath_connectservice(scn, &connect, "WMI CONTROL")) != EOK)
        goto conn_fail;
#endif
    if (!bypasswmi) {
        if ((status = wmi_unified_connect_htc_service(scn->wmi_handle, scn->htc_handle)) != EOK)
             goto conn_fail;
    }
#if defined(EPPING_TEST) && !defined(HIF_USB)
    if (eppingtest){
        extern A_STATUS epping_connect_service(struct ol_ath_softc_net80211 *scn);
        if ((status = epping_connect_service(scn)) != EOK)
             goto conn_fail;
    }
#endif
    if (scn->target_version == AR6004_VERSION_REV1_3) {
      if ((status = HIF_USB_connect_service(scn)) != EOK)
               goto conn_fail;
    }
    /*
     * give our connected endpoints some buffers
     */
#if 0
    ar6000_rx_refill(scn, scn->htt_control_ep);
    ar6000_rx_refill(scn, scn->htt_data_ep);
#endif

    /*
     * Since cookies are used for HTC transports, they should be
     * initialized prior to enabling HTC.
     */
    ol_cookie_init((void *)scn);


    /*
     * Start HTC
     */
    if ((status = htc_start(scn->htc_handle)) != A_OK) {
        goto conn_fail;
    }

    if (!bypasswmi) {
        /*
         * Wait for WMI event to be ready
         */
        if (scn->target_version == AR6004_VERSION_REV1_3) {
            scn->wmi_ready = TRUE;
            scn->wlan_init_status = TARGET_INIT_STATUS_SUCCESS;
        } else {
            if ((status = __ol_ath_check_wmi_ready(scn)) != EOK) {
                goto conn_fail1;
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() WMI is ready\n", __func__);

            if(scn->wlan_init_status != TARGET_INIT_STATUS_SUCCESS)
            {
              QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s Target wmi init failed with status %d\n", __func__,scn->wlan_init_status);
              status = ENODEV;
              goto conn_fail1;
            }
        }
        /* Communicate the wmi protocol verision to the target */
        if ((ol_ath_set_host_app_area(scn)) != EOK) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unable to set the host app area\n");
        }
    }

    // TODO is this needed
//            ar6000_target_config_wlan_params(arPriv);
    return EOK;

conn_fail1:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    if(scn->alloc_task_wqueue != NULL) {
        ATH_FLUSH_WQUEUE(scn->alloc_task_wqueue);
        ATH_DESTROY_WQUEUE(scn->alloc_task_wqueue);
        scn->alloc_task_wqueue = NULL;
    }
#endif

    hif_disable_isr((struct hif_opaque_softc *)scn->hif_hdl);
    htc_stop(scn->htc_handle);
conn_fail:
    return status;
}

int
ol_ath_disconnect_htc(struct ol_ath_softc_net80211 *scn)
{
    if (scn->htc_handle != NULL) {
        htc_stop(scn->htc_handle);
    }
    return 0;
}

#if QCA_AIRTIME_FAIRNESS
static u_int32_t
ol_ath_net80211_node_buf_held(struct ieee80211_node *ic)
{
    return 0;
}
#endif

#if ATH_BAND_STEERING
static bool
ol_ath_bs_set_params(struct ieee80211com *ic,
                     ieee80211_bsteering_lmac_param_t *params)
{
    return ol_txrx_set_inact_params((OL_ATH_SOFTC_NET80211(ic))->pdev_txrx_handle,
                                    params->inactivity_check_period,
                                    params->inactivity_threshold_normal,
                                    params->inactivity_threshold_overload);
}

static bool
ol_ath_bs_enable(struct ieee80211com *ic, bool enable)
{
    return ol_txrx_start_inact_timer((OL_ATH_SOFTC_NET80211(ic))->pdev_txrx_handle,
                                      enable);
}

static void
ol_ath_bs_set_overload(struct ieee80211com *ic, bool overload)
{
    ol_txrx_set_overload((OL_ATH_SOFTC_NET80211(ic))->pdev_txrx_handle,
                         overload);
}
#endif // ATH_BAND_STEERING

int ol_ath_pdev_set_param(struct ol_ath_softc_net80211 *scn,
                    uint32_t param_id, uint32_t param_value, uint8_t pdev_id)
{
    struct pdev_params pparam;

    qdf_mem_set(&pparam, sizeof(pparam), 0);
    pparam.param_id = param_id;
    pparam.param_value = param_value;

    return wmi_unified_pdev_param_send(scn->wmi_handle, &pparam, pdev_id);
}

static void
ol_ath_update_caps(struct ieee80211com *ic, target_capability_info *ev)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int32_t ampdu_exp = 0;
    u_int16_t caps  = 0;
    u_int16_t ciphercap = 0;
    /* setup ieee80211 flags */
    ieee80211com_clear_cap(ic, -1);
    ieee80211com_clear_athcap(ic, -1);
    ieee80211com_clear_athextcap(ic, -1);
    ieee80211com_clear_ciphercap(ic, -1);
    ieee80211com_set_phytype(ic, IEEE80211_T_OFDM);
    ieee80211com_set_cap(ic,IEEE80211_C_SHPREAMBLE);

    ieee80211com_set_cap(ic,
                     IEEE80211_C_IBSS           /* ibss, nee adhoc, mode */
                     | IEEE80211_C_HOSTAP       /* hostap mode */
                     | IEEE80211_C_MONITOR      /* monitor mode */
                     | IEEE80211_C_SHSLOT       /* short slot time supported */
                     | IEEE80211_C_PMGT         /* capable of power management*/
                     | IEEE80211_C_WPA          /* capable of WPA1+WPA2 */
                     | IEEE80211_C_BGSCAN       /* capable of bg scanning */
                  );

    /* Setting cipher cap */
    ciphercap = ( (1 << IEEE80211_CIPHER_WEP) |
               (1 << IEEE80211_CIPHER_TKIP) |
               (1 << IEEE80211_CIPHER_AES_OCB) |
               (1 << IEEE80211_CIPHER_AES_CCM) |
               (1 << IEEE80211_CIPHER_WAPI) |
               (1 << IEEE80211_CIPHER_CKIP) |
               (1 << IEEE80211_CIPHER_AES_CMAC) |
               (1 << IEEE80211_CIPHER_AES_CCM_256) |
               (1 << IEEE80211_CIPHER_AES_GCM) |
               (1 << IEEE80211_CIPHER_AES_GCM_256) |
               (1 << IEEE80211_CIPHER_AES_GMAC) |
               (1 << IEEE80211_CIPHER_AES_GMAC_256) |
               (1 << IEEE80211_CIPHER_NONE)
             );
    /*
     * AR9888 Family of Chips do not support GCMP and CCMP-256
     */
    if ( scn->target_type == TARGET_TYPE_AR9888 )
    {
        ciphercap &= (~((1 << IEEE80211_CIPHER_AES_CCM_256) |
                        (1 << IEEE80211_CIPHER_AES_GCM) |
                        (1 << IEEE80211_CIPHER_AES_GCM_256) |
                        (1 << IEEE80211_CIPHER_AES_GMAC) |
                        (1 << IEEE80211_CIPHER_AES_GMAC_256)) & 0xffff);
    }

    ieee80211com_set_ciphercap(ic, ciphercap);
    /* WMM enable */
    ieee80211com_set_cap(ic, IEEE80211_C_WME);

    scn->burst_enable = wmi_service_enabled(scn->wmi_handle,
                                    wmi_service_burst);

    if (wmi_service_enabled(scn->wmi_handle, wmi_service_ap_uapsd)) {
        ieee80211com_set_cap(ic, IEEE80211_C_UAPSD);
        IEEE80211_UAPSD_ENABLE(ic);
    }

    /* Default 11h to start enabled  */
    ieee80211_ic_doth_set(ic);
#if UMAC_SUPPORT_WNM
    /* Default WNM enabled   */
    ieee80211_ic_wnm_set(ic);
    /* WNM needs PS state of STA, so enable it in the FW */
    (void)ol_ath_pdev_set_param(scn,
                    wmi_pdev_peer_sta_ps_statechg_enable, 1, 0);
    scn->ps_report = 1;
#endif

#ifdef ATH_SUPPORT_WAPI

    if(scn->target_type == TARGET_TYPE_AR9888){
    /*WAPI HW engine support upto 300 Mbps (MCS15h),
      limiting the chains to 2*/
    ic->ic_num_wapi_rx_maxchains = 2;
    ic->ic_num_wapi_tx_maxchains = 2;
    } else {
      if(scn->wlan_resource_config.tx_chain_mask & 0x08)
            ic->ic_num_wapi_tx_maxchains = 4;
      else if(scn->wlan_resource_config.tx_chain_mask & 0x04)
            ic->ic_num_wapi_tx_maxchains = 3;
      else if(scn->wlan_resource_config.tx_chain_mask & 0x02)
            ic->ic_num_wapi_tx_maxchains = 2;
      else if(scn->wlan_resource_config.tx_chain_mask & 0x01)
            ic->ic_num_wapi_tx_maxchains = 1;

      if(scn->wlan_resource_config.rx_chain_mask & 0x08)
            ic->ic_num_wapi_rx_maxchains = 4;
      else if(scn->wlan_resource_config.rx_chain_mask & 0x04)
            ic->ic_num_wapi_rx_maxchains = 3;
      else if(scn->wlan_resource_config.rx_chain_mask & 0x02)
            ic->ic_num_wapi_rx_maxchains = 2;
      else if(scn->wlan_resource_config.rx_chain_mask & 0x01)
            ic->ic_num_wapi_rx_maxchains = 1;
    }
#endif
    /* 11n Capabilities */
    ieee80211com_set_num_tx_chain(ic,1);
    ieee80211com_set_num_rx_chain(ic,1);
    ieee80211com_clear_htcap(ic, -1);
    ieee80211com_clear_htextcap(ic, -1);
    if (ev->ht_cap_info & WMI_HOST_HT_CAP_ENABLED) {
        ieee80211com_set_cap(ic, IEEE80211_C_HT);
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SHORTGI40
                        | IEEE80211_HTCAP_C_CHWIDTH40
                        | IEEE80211_HTCAP_C_DSSSCCK40);
        if (ev->ht_cap_info & WMI_HOST_HT_CAP_HT20_SGI)  {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SHORTGI20);
        }
        if (ev->ht_cap_info & WMI_HOST_HT_CAP_DYNAMIC_SMPS) {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC);
        } else {
            ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED);
        }

        if (ev->ht_cap_info & WMI_HOST_HT_CAP_IBF_BFER) {
            ic->ic_implicitbf = 1 ;
        }

        ieee80211com_set_htextcap(ic, IEEE80211_HTCAP_EXTC_TRANS_TIME_5000
                        | IEEE80211_HTCAP_EXTC_MCS_FEEDBACK_NONE);
        ieee80211com_set_maxampdu(ic, IEEE80211_HTCAP_MAXRXAMPDU_65536);

        /* Force this to 8usec for now, instead of checking min_pkt_size_enable */
        if(scn->is_ar900b) {
            ieee80211com_set_mpdudensity(ic,IEEE80211_HTCAP_MPDUDENSITY_NA);
        }
        else {
            ieee80211com_set_mpdudensity(ic,IEEE80211_HTCAP_MPDUDENSITY_8);
        }
        ic->ic_mpdudensityoverride = 0;

        IEEE80211_ENABLE_AMPDU(ic);

        ieee80211com_set_num_rx_chain(ic, ev->num_rf_chains);
        ieee80211com_set_num_tx_chain(ic, ev->num_rf_chains);
        scn->wlan_resource_config.tx_chain_mask =  ((1 << ev->num_rf_chains) - 1);
        scn->wlan_resource_config.rx_chain_mask =  ((1 << ev->num_rf_chains) - 1);
        ieee80211com_set_tx_chainmask(ic,
                (u_int8_t) (scn->wlan_resource_config.tx_chain_mask));
        ieee80211com_set_rx_chainmask(ic,
                (u_int8_t) (scn->wlan_resource_config.rx_chain_mask));
    }

    /* Tx STBC is a 2-bit mask. Convert to ieee definition. */
    caps = (ev->ht_cap_info & WMI_HOST_HT_CAP_TX_STBC) >> WMI_HOST_HT_CAP_TX_STBC_MASK_SHIFT;
    ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_TXSTBC & (caps << IEEE80211_HTCAP_C_TXSTBC_S));


    /* Rx STBC is a 2-bit mask. Convert to ieee definition. */
    caps = (ev->ht_cap_info & WMI_HOST_HT_CAP_RX_STBC) >> WMI_HOST_HT_CAP_RX_STBC_MASK_SHIFT;
    ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_RXSTBC & (caps << IEEE80211_HTCAP_C_RXSTBC_S));

    if (ev->ht_cap_info & WMI_HOST_HT_CAP_LDPC) {
        ieee80211com_set_htcap(ic, IEEE80211_HTCAP_C_ADVCODING);
        if ((scn->target_type == TARGET_TYPE_AR900B) && (scn->target_revision == AR900B_REV_1)) {
            /* disable LDPC capability for Beeliner 1.0 */
            ieee80211com_set_ldpccap(ic,IEEE80211_HTCAP_C_LDPC_NONE);
        } else {
        /* enable LDPC capability */
        ieee80211com_set_ldpccap(ic, IEEE80211_HTCAP_C_LDPC_TXRX);
    }
    }

    /* 11n configuration */
    ieee80211com_clear_htflags(ic, -1);

    /*
     * Note that in the offload architecture chain_masks
     * and spatial_streams are synonymous
     */
    ieee80211com_set_spatialstreams(ic, ev->num_rf_chains);

    /*
     * Indicate we need the 802.11 header padded to a
     * 32-bit boundary for 4-address and QoS frames.
     */
    IEEE80211_ENABLE_DATAPAD(ic);

    /* Check whether the hardware is VHT capable */
    ieee80211com_clear_vhtcap(ic, -1);
    if (wmi_service_enabled(scn->wmi_handle, wmi_service_11ac)) {

        /* Copy the VHT capabilities information */
        ieee80211com_set_vhtcap(ic, ev->vht_cap_info);

        /* Adjust HT AMSDU len based on VHT MPDU len */
        if ((ev->vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_7935) ||
            (ev->vht_cap_info & IEEE80211_VHTCAP_MAX_MPDU_LEN_11454)) {
            ieee80211com_set_htcap(ic,IEEE80211_HTCAP_C_MAXAMSDUSIZE);
        } else {
            ieee80211com_clear_htcap(ic,IEEE80211_HTCAP_C_MAXAMSDUSIZE);
        }

        /* Adjust HT AMPDU len Exp  based on VHT MPDU len */
        ampdu_exp = ev->vht_cap_info >> IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S;
        switch (ampdu_exp) {
            case 0:
            case 1:
            case 2:
            case 3:
                ieee80211com_set_maxampdu(ic, ampdu_exp);
            break;

            default:
                ieee80211com_set_maxampdu(ic, IEEE80211_HTCAP_MAXRXAMPDU_65536);
            break;
        }


        /* Set the VHT  rate information */
        {
            /*  11ac spec states it is mandatory to support MCS 0-7 and NSS=1 */
            u_int16_t basic_mcs = 0xfffc;
            ol_ath_vht_rate_setup(ic, ev->vht_supp_mcs, 0, basic_mcs );

        }
        ic->ic_vht_ampdu = 64;
/* The default max amsdu value in FW for Beeliner family is 4
 * and for Peregrine is 3. So init the values accordingly.
 */
        if (scn->is_ar900b) {
            ic->ic_vht_amsdu = 4;
        } else {
            ic->ic_vht_amsdu = 3;
        }

        if (wmi_service_enabled(scn->wmi_handle, wmi_service_extended_nss_support)) {
            qdf_print("EXT NSS Supported\n");
            ic-> ic_fw_ext_nss_capable = 1;
        }
    }

    if (enable_mesh_support &&
                wmi_service_enabled(scn->wmi_handle, wmi_service_mesh)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Mesh Supported \n");
        ic->ic_mesh_vap_support = 1;
	    scn->wlan_resource_config.alloc_frag_desc_for_data_pkt = 1;
        scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_VDEV_MESH;
    }

    /* this should be updated from service bit map. This change is added temporarily untill firmware support is added*/
    if(scn->is_ar900b) {
        ic->ic_tso_support = 1;
        ic->ic_lro_support = 1;
        ic->ic_sg_support = 1;
        ic->ic_gro_support = 1;
        ic->ic_offload_tx_csum_support = 1;
        ic->ic_offload_rx_csum_support = 1;
        ic->ic_rawmode_support = 1;
        ic->ic_dynamic_grouping_support = 1;
        ic->ic_dpd_support = 1;
        ic->ic_aggr_burst_support = 1;
        ic->ic_qboost_support = 1;
        ic->ic_sifs_frame_support = 1;
        ic->ic_block_interbss_support = 1;
        ic->ic_disable_reset_support = 1;
        ic->ic_msdu_ttl_support = 1;
        ic->ic_ppdu_duration_support = 1;
        ic->ic_burst_mode_support = 1;
        ic->ic_peer_flow_control_support = 1;
    }
    ic->ic_promisc_support = 1;

#if 0 // ANISH DISABLED THIS ON BEELINER
    if (wmi_service_enabled(scn->wmi_handle, wmi_service_ratectrl)) {
        ol_txrx_enable_host_ratectrl(
                (OL_ATH_SOFTC_NET80211(ic))->pdev_txrx_handle, 1);
    }
#endif

    /* ToDo, check ev->sys_cap_info for  WMI_SYS_CAP_ENABLE and WMI_SYS_CAP_TXPOWER when it is available from FW */
    ieee80211com_set_cap(ic, IEEE80211_C_TXPMGT);

    ieee80211_wme_initglobalparams(ic);
}

extern unsigned int cfg_iphdr_pad;

void
ol_ath_set_default_tgt_config(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    target_resource_config  tgt_cfg = {
        .num_vdevs = CFG_TGT_NUM_VDEV_AR988X,
        .num_peers = CFG_TGT_NUM_PEERS + CFG_TGT_NUM_VDEV_AR988X, /* need to reserve an additional peer for each VDEV */
        .num_offload_peers = CFG_TGT_NUM_OFFLOAD_PEERS,
        .num_offload_reorder_buffs = CFG_TGT_NUM_OFFLOAD_REORDER_BUFFS,
        .num_peer_keys = CFG_TGT_NUM_PEER_KEYS,
        .num_tids = CFG_TGT_NUM_TIDS,
        .ast_skid_limit = CFG_TGT_AST_SKID_LIMIT,
        .tx_chain_mask = CFG_TGT_DEFAULT_TX_CHAIN_MASK_4SS,
        .rx_chain_mask = CFG_TGT_DEFAULT_RX_CHAIN_MASK_4SS,
        .rx_timeout_pri = { CFG_TGT_RX_TIMEOUT_LO_PRI, CFG_TGT_RX_TIMEOUT_LO_PRI, CFG_TGT_RX_TIMEOUT_LO_PRI, CFG_TGT_RX_TIMEOUT_HI_PRI },
#ifdef ATHR_WIN_NWF
        .rx_decap_mode = CFG_TGT_RX_DECAP_MODE_NWIFI,
#else
        .rx_decap_mode = CFG_TGT_RX_DECAP_MODE,
#endif
        .scan_max_pending_req = CFG_TGT_DEFAULT_SCAN_MAX_REQS,
        .bmiss_offload_max_vdev = CFG_TGT_DEFAULT_BMISS_OFFLOAD_MAX_VDEV,
        .roam_offload_max_vdev = CFG_TGT_DEFAULT_ROAM_OFFLOAD_MAX_VDEV,
        .roam_offload_max_ap_profiles = CFG_TGT_DEFAULT_ROAM_OFFLOAD_MAX_PROFILES,
        .num_mcast_groups = CFG_TGT_DEFAULT_NUM_MCAST_GROUPS,
        .num_mcast_table_elems = CFG_TGT_DEFAULT_NUM_MCAST_TABLE_ELEMS,
        .mcast2ucast_mode = CFG_TGT_DEFAULT_MCAST2UCAST_MODE,
        .tx_dbg_log_size = CFG_TGT_DEFAULT_TX_DBG_LOG_SIZE,
        .num_wds_entries = CFG_TGT_WDS_ENTRIES,
        .dma_burst_size = CFG_TGT_DEFAULT_DMA_BURST_SIZE,
        .mac_aggr_delim = CFG_TGT_DEFAULT_MAC_AGGR_DELIM,
        .rx_skip_defrag_timeout_dup_detection_check =
            CFG_TGT_DEFAULT_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK,
        .vow_config = CFG_TGT_DEFAULT_VOW_CONFIG,
        .gtk_offload_max_vdev = CFG_TGT_DEFAULT_GTK_OFFLOAD_MAX_VDEV,
        .num_msdu_desc = CFG_TGT_NUM_MSDU_DESC_AR900B,
        .max_frag_entries = 0,
        .max_peer_ext_stats = CFG_TGT_DEFAULT_MAX_PEER_EXT_STATS,
        .smart_ant_cap = 0,
        .BK_Minfree = 0,
        .BE_Minfree = 0,
        .VI_Minfree = 0,
        .VO_Minfree = 0,
        .rx_batchmode = 0,
        .tt_support = 0,
        .atf_config = 0,
        .iphdr_pad_config = 1,
#if PEER_CACHEING_HOST_ENABLE
        .num_active_peers = 0,
#endif
    };

    wmi_host_ext_resource_config tgt_ext_cfg = {
        .host_platform_config = 0,
        .fw_feature_bitmap = 0,
    };

#if 0
    WMI_SET_QWRAP(&tgt_cfg,0);
#if MESH_MODE_SUPPORT
    WMI_SET_ALLOC_FRAG(&tgt_cfg,0);
#endif
#endif
    if (scn->max_descs) {
        /* num_msdu_desc is initialized to CFG_TGT_NUM_MSDU_DESC_AR900B
	 * here it is re-initialized to user configured value.
	 */
        tgt_cfg.num_msdu_desc = scn->max_descs;
    }

    if (scn->target_type == TARGET_TYPE_AR9888) {
        tgt_cfg.tx_chain_mask = CFG_TGT_DEFAULT_TX_CHAIN_MASK_3SS;
        tgt_cfg.rx_chain_mask = CFG_TGT_DEFAULT_RX_CHAIN_MASK_3SS;
        tgt_cfg.num_msdu_desc = CFG_TGT_NUM_MSDU_DESC_AR988X;
        tgt_cfg.ast_skid_limit = CFG_TGT_AST_SKID_LIMIT_AR988X;
    } else if (scn->target_type == TARGET_TYPE_AR900B || \
                        scn->target_type == TARGET_TYPE_QCA9984) {
        tgt_cfg.num_vdevs = CFG_TGT_NUM_VDEV_AR900B;
        /* need to reserve an additional peer for each VDEV */
        tgt_cfg.num_peers = CFG_TGT_NUM_PEERS + CFG_TGT_NUM_VDEV_AR900B;
        tgt_cfg.num_tids     += CFG_TGT_NUM_VDEV_AR900B;
        tgt_cfg.tx_chain_mask = CFG_TGT_DEFAULT_TX_CHAIN_MASK_4SS;
        tgt_cfg.rx_chain_mask = CFG_TGT_DEFAULT_RX_CHAIN_MASK_4SS;

    } else if (scn->target_type == TARGET_TYPE_IPQ4019 || \
               scn->target_type == TARGET_TYPE_QCA9888) {
        tgt_cfg.num_vdevs = CFG_TGT_NUM_VDEV_AR900B;
        /* need to reserve an additional peer for each VDEV */
        tgt_cfg.num_peers = CFG_TGT_NUM_PEERS + CFG_TGT_NUM_VDEV_AR900B;
        tgt_cfg.num_tids     += CFG_TGT_NUM_VDEV_AR900B;
        tgt_cfg.tx_chain_mask = CFG_TGT_DEFAULT_TX_CHAIN_MASK_2SS;
        tgt_cfg.rx_chain_mask = CFG_TGT_DEFAULT_RX_CHAIN_MASK_2SS;
    }

#if QCA_AIRTIME_FAIRNESS
    if (ic->atf_mode && (scn->target_type == TARGET_TYPE_AR9888 &&
                            scn->target_version == AR9888_REV2_VERSION)) {
        if (ic->atf_msdu_desc) {
            if (ic->atf_msdu_desc < CFG_TGT_NUM_MSDU_DESC_AR988X) {
                tgt_cfg.num_msdu_desc = CFG_TGT_NUM_MSDU_DESC_AR988X;
            } else {
                tgt_cfg.num_msdu_desc = ic->atf_msdu_desc;
            }
        } else {
           tgt_cfg.num_msdu_desc = CFG_TGT_NUM_MSDU_DESC_ATF;
        }
    }
#endif

    /* reduce the peer/vdev if CFG_TGT_NUM_MSDU_DESC_AR900B exceeds 1000 */
    // TODO:

    tgt_ext_cfg.fw_feature_bitmap |= WMI_HOST_FW_FEATURE_BSS_CHANNEL_INFO_64;

#if  QCA_OL_RX_BATCHMODE
	tgt_cfg.rx_batchmode = 1;
#endif

    if (scn->host_80211_enable) {
        /*
         * To make the IP header begins at dword aligned address,
         * we make the decapsulation mode as Native Wifi.
         */
        tgt_cfg.rx_decap_mode = CFG_TGT_RX_DECAP_MODE_NWIFI;
    }

    {
        extern unsigned int OL_ACBKMinfree, OL_ACBEMinfree, OL_ACVIMinfree, OL_ACVOMinfree;

        /* Set the Min buffer free for each AC, from the module param values */
        tgt_cfg.BK_Minfree = OL_ACBKMinfree;
        tgt_cfg.BE_Minfree = OL_ACBEMinfree;
        tgt_cfg.VI_Minfree = OL_ACVIMinfree;
        tgt_cfg.VO_Minfree = OL_ACVOMinfree;

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s : AC Minfree buffer allocation through module param (umac.ko)\n", __func__);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO" OL_ACBKMinfree : %d\n", OL_ACBKMinfree);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO" OL_ACBEMinfree : %d\n", OL_ACBEMinfree);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO" OL_ACVIMinfree : %d\n", OL_ACVIMinfree);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO" OL_ACVOMinfree : %d\n", OL_ACVOMinfree);
    }

    if (scn->is_ar900b) {
        /* Configuring IP header padding, from module param value */
        tgt_cfg.iphdr_pad_config = cfg_iphdr_pad;
    } else {
        tgt_cfg.iphdr_pad_config = 0;
    }

    if (ic->ic_mesh_vap_support)  {
        tgt_cfg.num_vdevs = CFG_TGT_NUM_VDEV_MESH;
        }

    scn->wlan_resource_config = tgt_cfg;
    scn->wlan_ext_resource_config = tgt_ext_cfg;

    /* Init peer count variable */
    qdf_atomic_init(&scn->peer_count);
    qdf_atomic_inc(&scn->peer_count);
    qdf_atomic_add(scn->wlan_resource_config.num_peers, &scn->peer_count);
}

static void dbg_print_wmi_service_11ac(struct ol_ath_softc_net80211 *scn,
                                                target_capability_info *ev)
{
    if (wmi_service_enabled(scn->wmi_handle, wmi_service_11ac)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "num_rf_chain:0x%08x  ",ev->num_rf_chains);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ht_cap_info:0x%08x  ",ev->ht_cap_info);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "vht_cap_info:0x%08x  ",ev->vht_cap_info);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "vht_supp_mcs:0x%08x\n",ev->vht_supp_mcs);
    }
    else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n No WMI 11AC service event received\n");
    }
}


#define HOST_MEM_CHUNK_MAX_SIZE (256*1024) /* max size if 256k */
#define HOST_MEM_CHUNK_MAX_SIZE_POWER2 (8+10)
#define TXBF_CV_POOL0 2
#define TXBF_CV_POOL1 3
#define TXBF_CV_POOL2 4
#define HOST_CONTIGUOUS_MEM_CHUNK_REQUIRED 0x8
/**
 * allocate a chunk of memory at the index indicated and
 * if allocation fail allocate smallest size possiblr and
 * return number of units allocated.
 */
u_int32_t
ol_ath_alloc_host_mem_chunk(ol_scn_t scn, u_int32_t req_id, u_int32_t idx, u_int32_t num_units, u_int32_t unit_len, u_int32_t num_unit_info)
{
    qdf_dma_addr_t paddr;
#if !WIFI_MEM_MANAGER_SUPPORT
    u_int32_t ichunk = 0;
#else
	struct ieee80211com *ic = &scn->sc_ic;
#endif

    if (!num_units  || !unit_len)  {
        return 0;
    }
#if !WIFI_MEM_MANAGER_SUPPORT
    /*We have to skip smaller chunks memory allocation for TXBF_CV buffer  as Firmware is expecting continous memory*/
    if(!((num_unit_info & HOST_CONTIGUOUS_MEM_CHUNK_REQUIRED) && (req_id == TXBF_CV_POOL0 || req_id == TXBF_CV_POOL1 || req_id == TXBF_CV_POOL2)))
    {
        ichunk = ((num_units * unit_len) >> HOST_MEM_CHUNK_MAX_SIZE_POWER2);
        if (ichunk) {
            num_units = num_units / (ichunk + 1);
        }
    }
#endif

    scn->mem_chunks[idx].vaddr = NULL ;
    /** reduce the requested allocation by half until allocation succeeds */
    while(scn->mem_chunks[idx].vaddr == NULL && num_units ) {
#if WIFI_MEM_MANAGER_SUPPORT
        int intr_ctxt = (in_interrupt() || irqs_disabled()) ? 1 : 0;
        scn->mem_chunks[idx].vaddr = (uint32_t *) wifi_cmem_allocation(ic->interface_id, (CM_FWREQ + req_id), num_units*unit_len, (void *)scn->qdf_dev->drv_hdl , &paddr, intr_ctxt);
#else
        scn->mem_chunks[idx].vaddr = qdf_mem_alloc_consistent(
            scn->qdf_dev, &(((struct pci_dev *)(scn->qdf_dev->drv_hdl))->dev), num_units*unit_len, &paddr);
            /* qdf_get_dma_mem_context((&(scn->mem_chunks[idx])), memctx)); */
#endif
        if(scn->mem_chunks[idx].vaddr == NULL) {
            if (num_unit_info & HOST_CONTIGUOUS_MEM_CHUNK_REQUIRED) {
                return 0;
            } else {
                num_units = (num_units >> 1) ; /* reduce length by half */
            }
        } else {
           scn->mem_chunks[idx].paddr = paddr;
           scn->mem_chunks[idx].len = num_units*unit_len;
           scn->mem_chunks[idx].req_id =  req_id;
        }
    }
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s req_id %d idx %d num_units %d unit_len %d,\n",__func__,req_id, idx, num_units, unit_len);
    return num_units;
}


#define HOST_MEM_SIZE_UNIT 4

/*
 * allocate amount of memory requested by FW.
 *  input scn - scn data structure, update target config within this structure
 */
A_STATUS
ol_ath_alloc_host_mem (ol_scn_t scn, u_int32_t req_id, u_int32_t num_units, u_int32_t unit_len,u_int32_t num_unit_info)
{
    u_int32_t remaining_units,allocated_units,idx;
    /* adjust the length to nearest multiple of unit size */
    unit_len = (unit_len + (HOST_MEM_SIZE_UNIT - 1)) & (~(HOST_MEM_SIZE_UNIT - 1));
    idx = scn->num_mem_chunks ;
    remaining_units = num_units;
    while(remaining_units) {
        if (idx == MAX_MEM_CHUNKS ) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "REACHED MAX CHUNK LIMIT for memory units %d unit len %d requested by FW, only allocated %d \n",
                   num_units,unit_len, (num_units - remaining_units));
            scn->num_mem_chunks = idx;
            return A_ERROR;
        }

        allocated_units = ol_ath_alloc_host_mem_chunk(scn,req_id,  idx, remaining_units,unit_len,num_unit_info);
        if (allocated_units == 0) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "FAILED TO ALLOCATE memory unit len %d units requested %d units allocated %d \n",unit_len, num_units,(num_units - remaining_units));
            scn->num_mem_chunks = idx;
            return A_NO_MEMORY;
        }
        remaining_units -= allocated_units;
        ++idx;
    }
    scn->num_mem_chunks = idx;
    return A_OK;
}

static int ol_ath_get_sta_num(struct ol_ath_softc_net80211 *scn,
        int msdu_desc_size, int peer_size)
{
     /* If VoW is enabled, memory for TOTAL_VOW_ALLOCABLE number of descriptors are reserved
      * for VoW statsions. To accomadate this memory, number of peers is reduced to 16.
      * Incase, vow is configured such that it doesn't need all those memory, it can be used
      * to support more stations.
      */
    int sta_num = 0;

    if (scn->is_ar900b) {
        /* As of now no need to allocate any extra station for AR900B */
        sta_num = 0;
    } else if (scn->target_type == TARGET_TYPE_AR9888) {
        int num_vi_sta = VOW_GET_NUM_VI_STA(scn->vow_config);
        int num_vi_desc_per_sta = VOW_GET_DESC_PER_VI_STA(scn->vow_config);
    int total_vow_desc = num_vi_sta * num_vi_desc_per_sta;
    int total_free_desc = TOTAL_VOW_ALLOCABLE - total_vow_desc;

    if(total_free_desc > 0) {
        int bytes_avail = total_free_desc * msdu_desc_size;
        sta_num = bytes_avail / peer_size;
    }
    }
    return sta_num;
}

/*
 * Update target config supported in LARGE_AP feature.
 *  input scn - scn data structure
 */
static inline void ol_ath_update_large_ap_config(struct ol_ath_softc_net80211 *scn)
{
    /*sanity check*/
    if(scn == NULL)
        return;

    scn->wlan_resource_config.num_peers = CFG_TGT_NUM_PEERS_MAX;

    if (wmi_service_enabled(scn->wmi_handle, wmi_service_rtt)) {
        if (scn->wlan_resource_config.num_peers > CFG_TGT_NUM_RTT_PEERS_MAX)
            scn->wlan_resource_config.num_peers = CFG_TGT_NUM_RTT_PEERS_MAX;
    }

#if UNIFIED_SMARTANTENNA
    /* Make sure that number of peers is not exceeding smart antenna's MAX suported */
    if (scn->wlan_resource_config.smart_ant_cap) {
#if QCA_LTEU_SUPPORT
        if( !(scn->lteu_support) ) {
#endif
            scn->wlan_resource_config.num_peers =
                (scn->wlan_resource_config.num_peers > CFG_TGT_NUM_SMART_ANT_PEERS_MAX) ? \
                 CFG_TGT_NUM_SMART_ANT_PEERS_MAX : scn->wlan_resource_config.num_peers;
#if QCA_LTEU_SUPPORT
        }
#endif
    }
#endif
    if ((scn->wlan_resource_config.num_peers * 2) > CFG_TGT_NUM_TIDS_MAX) {
        /* one data tid per peer */
        scn->wlan_resource_config.num_tids = scn->wlan_resource_config.num_peers;

    } else if ((scn->wlan_resource_config.num_peers * 4) > CFG_TGT_NUM_TIDS_MAX) {
        /* two tids per peer */
        scn->wlan_resource_config.num_tids = scn->wlan_resource_config.num_peers * 2;
    } else {
        /* four tids per peer */
        scn->wlan_resource_config.num_tids = scn->wlan_resource_config.num_peers * 4;
    }

    if (scn->max_vdevs) {
        scn->wlan_resource_config.num_vdevs = scn->max_vdevs;
        scn->wlan_resource_config.num_peers += scn->max_vdevs;
    } else {
        if (scn->is_ar900b) {
            scn->wlan_resource_config.num_peers += CFG_TGT_NUM_VDEV_AR900B;
        } else {
            scn->wlan_resource_config.num_peers += CFG_TGT_NUM_VDEV_AR988X;
        }
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "LARGE_AP enabled. num_peers %d, num_vdevs %d, num_tids %d\n",
            scn->wlan_resource_config.num_peers,
            scn->wlan_resource_config.num_vdevs,
            scn->wlan_resource_config.num_tids);
}

/*
 * Update target config for VoW feature.
 *  input scn - scn data structure, update target config within this structure
 */
static inline void ol_ath_update_vow_config(struct ol_ath_softc_net80211 *scn)
{
    /*sanity check*/
    if(scn == NULL)
        return;

    /*VoW enabled*/
    if (scn->is_ar900b) {
    scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_VDEV_VOW;
#if PEER_CACHEING_HOST_ENABLE
        if(wmi_service_enabled(scn->wmi_handle, wmi_service_peer_caching)) {
            /* Configure VoW with Qcache enabled */
            scn->wlan_resource_config.num_peers = CFG_TGT_QCACHE_NUM_PEERS_VOW;
            scn->wlan_resource_config.num_active_peers = CFG_TGT_NUM_ACTIVE_PEERS_VOW +
                scn->wlan_resource_config.num_vdevs;
            scn->wlan_resource_config.num_tids = 2 * scn->wlan_resource_config.num_active_peers;
        } else
#endif
        {
            scn->wlan_resource_config.num_peers = CFG_TGT_NUM_PEERS_VOW +
                scn->wlan_resource_config.num_vdevs;
            scn->wlan_resource_config.num_tids = 2 * scn->wlan_resource_config.num_peers;
        }

    } else if (scn->target_type == TARGET_TYPE_AR9888) {
        scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_VDEV_VOW;
    scn->wlan_resource_config.num_peers = CFG_TGT_NUM_PEERS_VOW +
        CFG_TGT_NUM_VDEV_VOW + ol_ath_get_sta_num(scn, \
                MSDU_DESC_SIZE, MEMORY_REQ_FOR_PEER);
        scn->wlan_resource_config.num_tids =
            2 * ( scn->wlan_resource_config.num_vdevs +
                    scn->wlan_resource_config.num_peers );
        scn->wlan_resource_config.num_wds_entries = CFG_TGT_WDS_ENTRIES_VOW;
    }

#if UNIFIED_SMARTANTENNA
    /* Both Host and Firmware has Smart Antenna support */
    if (scn->wlan_resource_config.smart_ant_cap) {
#if QCA_LTEU_SUPPORT
        if( !(scn->lteu_support) ) {
#endif
            scn->wlan_resource_config.num_peers =
                ((scn->wlan_resource_config.num_peers > CFG_TGT_NUM_SMART_ANT_PEERS_MAX) ? \
                CFG_TGT_NUM_SMART_ANT_PEERS_MAX:(scn->wlan_resource_config.num_peers));
#if QCA_LTEU_SUPPORT
        }
#endif
    }
#endif
    scn->wlan_resource_config.vow_config = scn->vow_config;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VoW Enabled: Num peers = %d Num vdevs = %d Num TIDs = %d\n",
            scn->wlan_resource_config.num_peers,
            scn->wlan_resource_config.num_vdevs,
            scn->wlan_resource_config.num_tids );
}

#if PEER_CACHEING_HOST_ENABLE
/*
 * Update target config for Qcache feature.
 *  input scn - scn data structure, update target config within this structure
 */
static inline void ol_ath_update_peer_cache_config(struct ol_ath_softc_net80211 *scn)
{
    /*sanity check*/
    if(scn == NULL)
        return;

    scn->wlan_resource_config.num_peers = ((low_mem_system) ? (CFG_TGT_NUM_QCACHE_PEERS_MAX_LOW_MEM) :(CFG_TGT_NUM_QCACHE_PEERS_MAX)) + scn->wlan_resource_config.num_vdevs;

    if ((scn->max_active_peers) &&
        (!scn->max_descs) &&
        (scn->max_active_peers < CFG_TGT_QCACHE_ACTIVE_PEERS) ) {
        scn->wlan_resource_config.num_active_peers = scn->max_active_peers + \
                                                 scn->wlan_resource_config.num_vdevs;
    } else if (scn->max_descs) {
        scn->wlan_resource_config.num_active_peers = scn->max_active_peers + \
                                                 scn->wlan_resource_config.num_vdevs;
    } else {
        scn->wlan_resource_config.num_active_peers = CFG_TGT_QCACHE_ACTIVE_PEERS + \
                                                 scn->wlan_resource_config.num_vdevs;
    }

    scn->wlan_resource_config.num_tids = scn->wlan_resource_config.num_active_peers * 2;


    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "Peer Caching Enabled ; num_peers = %d, num_active_peers = %d num_tids = %d, num_vdevs = %d\n",
            scn->wlan_resource_config.num_peers, scn->wlan_resource_config.num_active_peers,
            scn->wlan_resource_config.num_tids, scn->wlan_resource_config.num_vdevs );
}
#endif

#if ATH_SUPPORT_WRAP
/*
 * Update target config when Qwrap is enabled through module param via wifi UCI script
 *  input scn - scn data structure, update target config within this structure
 */
static inline void ol_ath_update_qwrap_config(struct ol_ath_softc_net80211 *scn)
{
    /*sanity check*/
    if(scn == NULL)
        return;

    scn->wlan_resource_config.qwrap_config = scn->qwrap_enable;

    if (scn->target_type == TARGET_TYPE_AR9888)
        scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_WRAP_VDEV_AR988X;
    else if (scn->target_type == TARGET_TYPE_QCA9984)
        scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_WRAP_VDEV_QCA9984;
    else if (scn->target_type == TARGET_TYPE_IPQ4019)
        scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_WRAP_VDEV_IPQ4019;
    else
        scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_WRAP_VDEV_AR900B;

    /* Every sta vdev target need 2 peer ( self & bss beer )
     * To no of peers in Qwrap =
     * no of sta vdev (to no of vdev - 1 ap vdev ) * 2 peer
     * + 1 ap vdev peer
     * + max wireless peers supported in AP vdev
     */
    if (scn->target_type == TARGET_TYPE_AR9888)
        scn->wlan_resource_config.num_peers = (( CFG_TGT_NUM_WRAP_VDEV_AR988X -1 ) * 2 ) + 1 + CFG_TGT_NUM_WRAP_PEERS_MAX_AR988X;
    else if (scn->target_type == TARGET_TYPE_QCA9984)
        scn->wlan_resource_config.num_peers = (( CFG_TGT_NUM_WRAP_VDEV_QCA9984 -1 ) * 2 ) + 1 + CFG_TGT_NUM_WRAP_PEERS_MAX_QCA9984;
    else if (scn->target_type == TARGET_TYPE_IPQ4019)
        scn->wlan_resource_config.num_peers = (( CFG_TGT_NUM_WRAP_VDEV_IPQ4019 -1 ) * 2 ) + 1 + CFG_TGT_NUM_WRAP_PEERS_MAX_IPQ4019;
    else
        scn->wlan_resource_config.num_peers = (( CFG_TGT_NUM_WRAP_VDEV_AR900B -1 ) * 2 ) + 1 + CFG_TGT_NUM_WRAP_PEERS_MAX_AR900B;

    /* Wrt Qwrap, num_peers & num_active_peers are same.
     * Target recommends host to set the num_active_peers to
     * 0 and target will reset num_active_peers accordingly
     * based on target final total num_peers.
     */
    scn->wlan_resource_config.num_active_peers = 0;
    scn->wlan_resource_config.num_tids = scn->wlan_resource_config.num_peers * 2;

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Qwrap Enabled ; num_peers = %d, num_active_peers = %d num_tids = %d, num_vdevs = %d\n",
           scn->wlan_resource_config.num_peers, scn->wlan_resource_config.num_active_peers,
           scn->wlan_resource_config.num_tids, scn->wlan_resource_config.num_vdevs );
}
#endif

/**
* @brief    Check if firmware announced 160/80+80 MHz wireless modes
*           and vhtcap entries are valid and in sync with each other.
*
* @param ev pointer to wmi_service_ready_event
*
* @return true if capabilities are valid or asserts otherwise.
*/
bool validate_160_80p80_fw_capabilities(struct ol_ath_softc_net80211 *scn, uint8_t *evt_buf)
{
    bool wireless_mode_160mhz = false;
    bool wireless_mode_80p80mhz = false;
    bool vhtcap_160mhz = false;
    bool vhtcap_80p80_160mhz = false;
    bool vhtcap_160mhz_sgi = false;
    bool valid = false;
    target_capability_info ev;

    /* NOTE: Host driver gets vht capability and supported channel
     * width / channel frequency range from FW/HALPHY and obeys it.
     * Host driver is unaware of any physical filters or any other
     * hardware factors that can impact these capabilities.
     * These need to be correctly determined by firmware.
     */

    /* This table lists all valid and invalid combinations
     *   WMODE160 WMODE80_80  VHTCAP_160 VHTCAP_80+80_160  Is Combination valid ?
     *      0         0           0              0                 YES
     *      0         0           0              1                 NO
     *      0         0           1              0                 NO
     *      0         0           1              1                 NO
     *      0         1           0              0                 NO
     *      0         1           0              1                 NO
     *      0         1           1              0                 NO
     *      0         1           1              1                 NO
     *      1         0           0              0                 NO
     *      1         0           0              1                 NO
     *      1         0           1              0                 YES
     *      1         0           1              1                 NO
     *      1         1           0              0                 NO
     *      1         1           0              1                 YES
     *      1         1           1              0                 NO
     *      1         1           1              1                 NO
     */

     /* NOTE: Last row in above table is invalid because value corresponding
      * to both VHTCAP_160 and VHTCAP_80+80_160 being set is reserved as per
      * 802.11ac. Only one of them can be set at a time.
      */

    wmi_extract_hal_reg_cap(scn->wmi_handle, evt_buf,  &scn->hal_reg_capabilities);
    wmi_get_target_cap_from_service_ready(scn->wmi_handle, evt_buf, &ev);

    wireless_mode_160mhz = ol_regdmn_get_160mhz_support(&(scn->hal_reg_capabilities));
    wireless_mode_80p80mhz = ol_regdmn_get_80p80mhz_support(&(scn->hal_reg_capabilities));
    vhtcap_160mhz = ieee80211_get_160mhz_vhtcap(ev.vht_cap_info);
    vhtcap_80p80_160mhz = ieee80211_get_80p80_160mhz_vhtcap(ev.vht_cap_info);
    vhtcap_160mhz_sgi = ieee80211_get_160mhz_shortgi_vhtcap(ev.vht_cap_info);

    if (!(wireless_mode_160mhz || wireless_mode_80p80mhz ||
        vhtcap_160mhz || vhtcap_80p80_160mhz)) {
        valid =  true;
    } else if (wireless_mode_160mhz && !wireless_mode_80p80mhz &&
       vhtcap_160mhz && !vhtcap_80p80_160mhz) {
        valid = true;
    } else if (wireless_mode_160mhz && wireless_mode_80p80mhz &&
        !vhtcap_160mhz && vhtcap_160mhz_sgi) {
        valid = true;
    }

    if (valid == true) {
        /* Ensure short GI for 160 MHz is enabled
         * only if 160/80+80 is supported.
         */
        if (vhtcap_160mhz_sgi &&
            !(vhtcap_160mhz || vhtcap_80p80_160mhz)) {
            valid = false;
        }
    }

    /* Invalid config specified by FW */
    if (valid == false) {
        qdf_print("%s: ERROR: Invalid 160/80+80 MHz config"
                     " specified by FW. Take care of it first\n", __func__);

        qdf_print("wireless_mode_160mhz: %d, wireless_mode_80p80mhz: %d"
                     "vhtcap_160mhz: %d, vhtcap_80p80_160mhz: %d, "
                     "vhtcap_160mhz_sgi: %d\n",
                     wireless_mode_160mhz, wireless_mode_80p80mhz,
                     vhtcap_160mhz, vhtcap_80p80_160mhz, vhtcap_160mhz_sgi);
    }
    return valid;
}

static uint8_t ol_ath_version_check(struct ol_ath_softc_net80211 *scn, uint8_t *evt_buf)
{
    A_UINT8 ver_mismatch=0;
	struct wmi_host_fw_ver fw_ver, *ev;

	ev = &fw_ver;

	if(wmi_extract_fw_version(scn->wmi_handle, evt_buf, ev) ==
		QDF_STATUS_SUCCESS) {
	  /* update the version info in the scn for the OS-es to check
	  */

	  QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Firmware_Build_Number:%d \n",VER_GET_BUILD_NUM(ev->sw_version_1));

	  /* Check if the host driver is compatible with the RAM fw version.
	   * If any of the Major/Minor/Patch/BuildNum mismatches, fail attach.
	   */
	  if (VER_GET_MAJOR(ev->sw_version) != __VER_MAJOR_) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("host/RAM_fw Major Ver Mismatch: H:0x%X, F:0x%X ! \n",
			 __VER_MAJOR_, VER_GET_MAJOR(ev->sw_version)));
		ver_mismatch=1;
	  }

	  if (VER_GET_MINOR(ev->sw_version) != __VER_MINOR_) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("host/RAM_fw Minor Ver Mismatch: H:0x%X, F:0x%X ! \n",
			 __VER_MINOR_, VER_GET_MINOR(ev->sw_version)));
		ver_mismatch=1;
	  }

	  if (VER_GET_RELEASE(ev->sw_version_1) != __VER_RELEASE_) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("host/RAM_fw Patch Ver Mismatch: H:0x%X, F:0x%X ! \n",
			 __VER_RELEASE_, VER_GET_RELEASE(ev->sw_version_1)));
		ver_mismatch=1;
	  }

	  if (VER_GET_BUILD_NUM(ev->sw_version_1) != __BUILD_NUMBER_) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
			("host/RAM_fw Build Ver Mismatch: H:0x%X, F:0x%X ! \n",
			 __BUILD_NUMBER_, VER_GET_BUILD_NUM(ev->sw_version_1)));
		ver_mismatch=1;
	  }

	  /* update the version info in the scn for the OS-es to check
	  */
	  scn->version.wlan_ver = ev->sw_version;
	  scn->version.wlan_ver_1 = ev->sw_version_1;
	}
    scn->is_version_match = !ver_mismatch;

    return ver_mismatch;
}

static int ol_ath_handle_host_mem_req(struct ol_ath_softc_net80211 *scn, uint8_t *evt_buf)
{
    uint8_t num_mem_reqs;
    host_mem_req *mem_reqs;
    int i, idx;
    A_STATUS status = A_OK;

    mem_reqs = wmi_extract_host_mem_req_from_service_ready(scn->wmi_handle, evt_buf, &num_mem_reqs);

    /* allocate memory requested by FW */
    ASSERT (num_mem_reqs <= WMI_MAX_MEM_REQS);
    if (num_mem_reqs) {
        u_int32_t num_units;
        for (i = 0;i < FW_PRIORITY_MAX;i++) {
            for(idx=0;idx < num_mem_reqs; ++idx) {
                if (((i == FW_MEM_HIGH_PRIORITY) && (mem_reqs[idx].num_unit_info & HOST_CONTIGUOUS_MEM_CHUNK_REQUIRED))
                        || ((i == FW_MEM_LOW_PRIORITY) && (!(mem_reqs[idx].num_unit_info & HOST_CONTIGUOUS_MEM_CHUNK_REQUIRED)))) {
                    /* First allocate the memory that requires coninuous memory */
                    num_units = mem_reqs[idx].num_units;
                    if ( mem_reqs[idx].num_unit_info ) {
                        if  ( mem_reqs[idx].num_unit_info & NUM_UNITS_IS_NUM_PEERS ) {
                            /* number of units to allocate is number of peers, 1 extra for self peer on target */
                            /* this needs to be fied, host and target can get out of sync */
                            num_units = scn->wlan_resource_config.num_peers + 1;
                        }
#if PEER_CACHEING_HOST_ENABLE
                        if  (mem_reqs[idx].num_unit_info & NUM_UNITS_IS_NUM_ACTIVE_PEERS) {
                            /* Request to allocate memory using num_active_peers in qcache.
                             * if qcache is disabled in host, then it should allocate
                             * memory for num_peers instead of num_active_peers.
                             * */
                            if( scn->wlan_resource_config.num_active_peers ) {
                                num_units = scn->wlan_resource_config.num_active_peers + 1;
                            } else {
                                num_units = scn->wlan_resource_config.num_peers + 1;
                            }
                        }
#endif
                    }
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"idx %d req %d  num_units %d num_unit_info %d unit size %d actual units %d \n",idx,
                            mem_reqs[idx].req_id,
                            mem_reqs[idx].num_units,
                            mem_reqs[idx].num_unit_info,
                            mem_reqs[idx].unit_size,
                            num_units);
                    status = ol_ath_alloc_host_mem(scn, mem_reqs[idx].req_id,
                            num_units,
                            mem_reqs[idx].unit_size,mem_reqs[idx].num_unit_info);
                    if (status == A_ERROR) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() scn:(%p) num_mem_chunk exceeds supported number\n", __func__, scn);
                        return -1;
                    } else if (status == A_NO_MEMORY) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s() scn:(%p) Mem allocation failure \n", __func__, scn);
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}
int
ol_ath_service_ready_event(ol_scn_t scn_handle, uint8_t *evt_buf, uint16_t len)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)scn_handle;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ol_ath_target_cap target_cap;
    int host_num_peers = 0;
    int val = 0;
    uint32_t  period, duration;
    int coex_ss_id;
#if UNIFIED_SMARTANTENNA
    unsigned int smart_ant_enable = 0;
#endif
    //A_STATUS status = A_OK;
    target_capability_info ev;


    if (ol_ath_version_check(scn, evt_buf)) {
        /* OS-es to decide how to handle version mismatch.
        */

    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,
                ("host/RAM_fw uses same Ver: Major:0x%X, Minor:0x%X, Release:0x%X, Build:0x%X \n",
                 __VER_MAJOR_, __VER_MINOR_, __VER_RELEASE_,  __BUILD_NUMBER_));
    }
    /* wmi service is ready */
    wmi_save_service_bitmap(scn->wmi_handle, evt_buf);

    wmi_extract_hal_reg_cap(scn->wmi_handle, evt_buf,  &scn->hal_reg_capabilities);

    qdf_print("FW wireless modes: 0x%x\n",
        (scn->hal_reg_capabilities.wireless_modes));

    /* Check if firmware announced 160/80+80 MHz wireless modes and vhtcap
     * entries are valid and in sync with each other.
     */
    if (false == validate_160_80p80_fw_capabilities(scn, evt_buf)) {
        /* FW anounced 160/80+80 MHz wireless modes and vhtcap entries
         * are either invalid or out of sync.
         * Set invalid flag to let attach related main thread know about failure.
         * Do not return from here and let both wmi_service_ready and wmi_ready
         * events arrive before we fail. This will allow all inconsistencies
         * from these two events to be examined together before the main thread
         * decides to declare the attach a failure.
         */
        scn->invalid_vht160_info = TRUE;
    }

    wmi_get_target_cap_from_service_ready(scn->wmi_handle, evt_buf, &ev);

    scn->phy_capability = ev.phy_capability;
    scn->max_frag_entry = ev.max_frag_entry;

    /* Dump service ready event for debugging */
    dbg_print_wmi_service_11ac(scn, &ev);

    if (wmi_service_enabled(scn->wmi_handle, wmi_service_ext_res_cfg_support)) {
        scn->wlan_ext_resource_config.host_platform_config = ol_ath_get_host_pltfrm_mode(scn);
        if (scn->wlan_ext_resource_config.host_platform_config < 0) {
            qdf_print("!!! Host Mode Selection for %d TGT Type FAILED !!!\n", scn->target_type);
            goto out;
        }
        scn->hybrid_mode = 1;
#if QCA_LTEU_SUPPORT
        if (scn->lteu_support) {
            scn->wlan_ext_resource_config.fw_feature_bitmap |= WMI_HOST_FW_FEATURE_LTEU_SUPPORT;
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "LTEu enabled. lteu_support %d\n",
                    scn->wlan_ext_resource_config.fw_feature_bitmap & WMI_HOST_FW_FEATURE_LTEU_SUPPORT);
        }
#endif
        if (wmi_service_enabled(scn->wmi_handle, wmi_service_coex_gpio)) {
            if (scn->target_type == TARGET_TYPE_IPQ4019) {
                /* Check if btcoex is supported in HW or not from DT */
#ifdef ATH_AHB
                ol_ath_check_btcoex_support(scn);
#endif

                if (scn->btcoex_support) {
                    scn->wlan_ext_resource_config.fw_feature_bitmap |= WMI_HOST_FW_FEATURE_COEX_GPIO_SUPPORT;

                    if (scn->btcoex_gpio) {
                        scn->coex_version = COEX_VERSION_2;
                        scn->wlan_ext_resource_config.wlan_priority_gpio = scn->btcoex_gpio;
                        scn->btcoex_enable = 1;

                        if (wmi_service_enabled(scn->wmi_handle, wmi_service_btcoex_duty_cycle)) {
                            scn->btcoex_duty_cycle = 1;
                        }
                    } else if (scn->coex_gpio_pin_1 && scn->coex_gpio_pin_2 && scn->coex_gpio_pin_3 &&
                               wmi_service_enabled(scn->wmi_handle, wmi_service_4_wire_coex_support)) {
                        scn->coex_version = COEX_VERSION_4;
                        scn->wlan_ext_resource_config.coex_version = scn->coex_version;
                        scn->wlan_ext_resource_config.coex_gpio_pin_1 = scn->coex_gpio_pin_1;
                        scn->wlan_ext_resource_config.coex_gpio_pin_2 = scn->coex_gpio_pin_2;
                        scn->wlan_ext_resource_config.coex_gpio_pin_3 = scn->coex_gpio_pin_3;
                    }
                }
            } else {
                scn->coex_version = COEX_VERSION_3;
                scn->btcoex_support = 1;
                scn->wlan_ext_resource_config.fw_feature_bitmap |= WMI_HOST_FW_FEATURE_COEX_GPIO_SUPPORT;
                scn->wlan_ext_resource_config.wlan_priority_gpio = 0;
                scn->btcoex_enable = 1;
            }
        }
        qdf_print("wmi_service_coex_gpio %d, wmi_service_4_wire_coex_support %d, coex_version %d\n",
                  wmi_service_enabled(scn->wmi_handle, wmi_service_coex_gpio),
                  wmi_service_enabled(scn->wmi_handle, wmi_service_4_wire_coex_support),
                  scn->coex_version);

        scn->wlan_ext_resource_config.fw_feature_bitmap |= WMI_HOST_FW_FEATURE_VDEV_STATS;
        wmi_send_ext_resource_config(scn->wmi_handle, &scn->wlan_ext_resource_config);
    } else {
        scn->hybrid_mode = 0;
    }

out:
    scn->thermal_param.tt_support = wmi_service_enabled(scn->wmi_handle, wmi_service_tt);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: tt_support: %d\n", __func__, scn->thermal_param.tt_support);

    scn->periodic_chan_stats = wmi_service_enabled(scn->wmi_handle,
                                     wmi_service_periodic_chan_stat_support);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: periodic_chan_stats: %d\n",
                     __func__, scn->periodic_chan_stats);

    scn->sw_cal_support_check_flag = wmi_service_enabled(scn->wmi_handle,
                                     wmi_service_check_cal_version);
    qdf_print("%s: sw_cal_support_check_flag: %d\n",__func__, scn->sw_cal_support_check_flag);

#if UNIFIED_SMARTANTENNA

    smart_ant_enable = ((wmi_service_enabled(scn->wmi_handle,
                    wmi_service_smart_antenna_sw_support)
                &&  wmi_service_enabled(scn->wmi_handle,
                    wmi_service_smart_antenna_hw_support) && scn->enable_smart_antenna)
                || (wmi_service_enabled(scn->wmi_handle,
                    wmi_service_smart_antenna_sw_support)
                && scn->sa_validate_sw));

    if (smart_ant_enable) {
        scn->wlan_resource_config.smart_ant_cap = 1;
    }
#endif


#if PEER_CACHEING_HOST_ENABLE
    if (wmi_service_enabled(scn->wmi_handle, wmi_service_peer_caching) &&
            !(scn->vow_config >> 16)) {

        ol_ath_update_peer_cache_config(scn);

    } else
#endif
    {
        if (wmi_service_enabled(scn->wmi_handle, wmi_service_ratectrl_cache) &&
                wmi_service_enabled(scn->wmi_handle, wmi_service_iram_tids) &&
                !(scn->vow_config >> 16)) {

            ol_ath_update_large_ap_config(scn);

        } else if(scn->vow_config>>16) {
            ol_ath_update_vow_config(scn);
        }
    }

#if QCA_AIRTIME_FAIRNESS
    if (wmi_service_enabled(scn->wmi_handle, wmi_service_atf))
    {
       /*Need to add host input if support this feature, if yes, add sta number configuration for resoures as VoW????*/
       ic->atf_fmcap = 1;
       if(ic->atf_mode)
       {
          scn->wlan_resource_config.atf_config = ic->atf_fmcap; /*Before here, should add if host need to support this one*/
#if PEER_CACHEING_HOST_ENABLE
          if (wmi_service_enabled(scn->wmi_handle, wmi_service_peer_caching)) {
              /* For Cascade/Beeliner/Dakota platform association can be supported
               * for more than num_active_peers. So avoid the limitation for these
               * platforms. Note that air time, however, is guaranteed only up to
               * num_active_peers.
               */
              if(!scn->is_ar900b) {
                  scn->wlan_resource_config.num_peers = scn->wlan_resource_config.num_active_peers;
              }
          }
          QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Airtime Fairness: num_peers=%d num_active_peer=%d\n",scn->wlan_resource_config.num_peers,
                  scn->wlan_resource_config.num_active_peers);
#endif
          if (scn->target_type == TARGET_TYPE_AR9888 && scn->target_version == AR9888_REV2_VERSION){
              if (ic->atf_max_vdevs) {
                  scn->wlan_resource_config.num_vdevs = ic->atf_max_vdevs;
                  if (ic->atf_peers) {
                      scn->wlan_resource_config.num_peers = ic->atf_peers +
                                         scn->wlan_resource_config.num_vdevs;
                  } else {
                      scn->wlan_resource_config.num_peers = CFG_TGT_NUM_PEERS_ATF +
                                         scn->wlan_resource_config.num_vdevs;
                  }
              } else if (ic->atf_peers) {
                    scn->wlan_resource_config.num_peers = ic->atf_peers + CFG_TGT_NUM_VDEV_AR988X;
              } else
                  scn->wlan_resource_config.num_peers = CFG_TGT_NUM_PEERS_ATF + CFG_TGT_NUM_VDEV_AR988X;

              QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ATF: peers = %d, vdevs = %d ",
                        scn->wlan_resource_config.num_peers, scn->wlan_resource_config.num_vdevs);
          }

/*          scn->wlan_resource_config.num_vdevs = CFG_TGT_NUM_VDEV_ATF;
          scn->wlan_resource_config.num_peers = CFG_TGT_NUM_PEERS_ATF;
          scn->wlan_resource_config.num_tids = CFG_TGT_NUM_TIDS_ATF;
          scn->wlan_resource_config.num_wds_entries = CFG_TGT_WDS_ENTRIES_ATF;
          printk("Initialization configuration, vdevs=%d,peers=%d,tids=%d,wds_entry=%d\n",scn->wlan_resource_config.num_vdevs,
                  scn->wlan_resource_config.num_peers,scn->wlan_resource_config.num_tids,scn->wlan_resource_config.num_wds_entries);*/
       }
    }
#endif

#if ATH_SUPPORT_WRAP
     if (scn->qwrap_enable ==1) {
         ol_ath_update_qwrap_config(scn);
     }
#endif

#if QCA_LTEU_SUPPORT
        if (scn->wlan_ext_resource_config.fw_feature_bitmap & WMI_HOST_FW_FEATURE_LTEU_SUPPORT) {
            /* There is a target aseert seen, so temporarily
             * increasing num_vdevs to 16 for LTEu. Ideally,
             * it should be 1. */
            scn->wlan_resource_config.num_peers = 10;
            scn->wlan_resource_config.num_peers += scn->wlan_resource_config.num_vdevs;
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "LTEu enabled. num_peers %d, num_vdevs %d, num_tids %d\n",
                scn->wlan_resource_config.num_peers,
                scn->wlan_resource_config.num_vdevs,
                scn->wlan_resource_config.num_tids);
        }
#endif

#if 0
        /* wmi_service_bitmap will be maintained in WMI layer. Should APIs to get access to these */
    OS_MEMCPY(target_cap.wmi_service_bitmap,scn->wmi_service_bitmap,sizeof(scn->wmi_service_bitmap));
#endif

     /*
      * Ext per vap stats can be enabled in FW only if max number of peers is restricted to 240
      * Support is provided to config max_peers to 240 through module_param. So if module_param
      * value exists, and it is less than scn->wlan_resource_config.num_peers, then override
      * scn->wlan_resource_config.num_peers
      */
    if ((scn->max_peers > scn->wlan_resource_config.num_active_peers) && (scn->max_peers < (scn->wlan_resource_config.num_peers - scn->wlan_resource_config.num_vdevs))) {
        scn->wlan_resource_config.num_peers = scn->max_peers + scn->wlan_resource_config.num_vdevs;
        qdf_print("Ext stats enabled. num_peers %d, num_vdevs %d, num_tids %d\n",
                                                  scn->wlan_resource_config.num_peers,
                                                  scn->wlan_resource_config.num_vdevs,
                                                  scn->wlan_resource_config.num_tids);
    }

    target_cap.wlan_resource_config = scn->wlan_resource_config;

    /* call back into  os shim with the services bitmap and resource config to let
     * the os shim layer modify it according to its needs and requirements */
    if (scn->cfg_cb) {
        scn->cfg_cb(scn, &target_cap);
#if 0
        /* TODO - Why should cfg callback modify FW service bitmap??
         * Disable it for now and remove it if not required */
        OS_MEMCPY(scn->wmi_service_bitmap,target_cap.wmi_service_bitmap, sizeof(scn->wmi_service_bitmap));
#endif
        scn->wlan_resource_config = target_cap.wlan_resource_config;
    }

    ol_ath_update_caps(ic, &ev);

    wmi_extract_hal_reg_cap(scn->wmi_handle, evt_buf,  &scn->hal_reg_capabilities);

    scn->max_tx_power = ev.hw_max_tx_power;
    scn->min_tx_power = ev.hw_min_tx_power;

    scn->txpowlimit2G = scn->max_tx_power;
    scn->txpowlimit5G = scn->max_tx_power;
    scn->txpower_scale = WMI_HOST_TP_SCALE_MAX;

    ieee80211com_set_txpowerlimit(ic, scn->max_tx_power);

    ol_regdmn_attach(scn);

    ol_regdmn_set_regdomain(scn->ol_regdmn_handle, scn->hal_reg_capabilities.eeprom_rd);
    ol_regdmn_set_regdomain_ext(scn->ol_regdmn_handle, scn->hal_reg_capabilities.eeprom_rd_ext);

    if(ol_ath_handle_host_mem_req(scn, evt_buf) < 0) {
        qdf_print("Failed to allocate host memory for FW\n");
        return -1;
    }
    /* Update the peer count variable */
    qdf_atomic_set(&scn->peer_count, 0);
    qdf_atomic_inc(&scn->peer_count);
    host_num_peers = scn->wlan_resource_config.num_peers;

#if ATH_SUPPORT_WRAP
    /* This adjustment is made so that the number of peers
     * in host and FW become equal. Host is not sending a peer
     * create event when creating a sta which leads to mismatch
     * in peer count between host and FW */
    if (scn->qwrap_enable == 1 ) {
        host_num_peers = host_num_peers - (scn->wlan_resource_config.num_vdevs - 1);
    }
#endif
    qdf_atomic_add(host_num_peers, &scn->peer_count);


    if (wmi_service_enabled(scn->wmi_handle,
                                   wmi_service_mgmt_tx_wmi)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WMI mgmt sevice enabled\n");

    }
    if (!wmi_service_enabled(scn->wmi_handle,
                wmi_service_ext_msg)) {
        /* No service extended message support.
         * Send INIT command immediately
         * */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No EXT_MSG send INIT now\n");
        scn->wmi_service_ready = TRUE;

        wmi_unified_init_cmd_send(scn->wmi_handle, &scn->wlan_resource_config,
                scn->num_mem_chunks, scn->mem_chunks);
    } else {
        /* Wait for service extended message.
         * Send INIT command immediately
         * */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Wait for EXT_MSG\n");
    }

    ol_ath_check_bandfilter_switch_gpio_support(scn);
    if(scn->band_filter_switch_support){
	if(wmi_service_enabled(scn->wmi_handle,wmi_service_band_filter_switch_support)) {
            struct band_filter_select_params param_gpio;
	    qdf_print("wmi band filter switch gpio num:%d\n",scn->band_filter_switch_gpio);
	    param_gpio.gpio_pin_number = scn->band_filter_switch_gpio;
	    wmi_unified_send_band_filter_select_cmd(scn->wmi_handle,&param_gpio);
	}else
	    qdf_print("Bandfilter switch dts support there.but FW support not there\n");
    }

    if (scn->btcoex_enable) {
        val = WMI_HOST_PDEV_VI_PRIORITY_BIT |
              WMI_HOST_PDEV_BEACON_PRIORITY_BIT |
              WMI_HOST_PDEV_MGMT_PRIORITY_BIT;

        if (ol_ath_btcoex_wlan_priority(scn, val) == EOK) {
            scn->btcoex_wl_priority = val;
        }
        if (scn->btcoex_duty_cycle) {
            period = DEFAULT_PERIOD;
            duration = DEFAULT_WLAN_DURATION;
            if ( ol_ath_btcoex_duty_cycle(scn,period,duration) == EOK ) {
                scn->btcoex_period = period;
                scn-> btcoex_duration = duration;
            }
        }
    }
    if (scn->coex_version == COEX_VERSION_4) {
        coex_ss_id = (THREAD_SUBSYSTEM_ID << 24) | (BT_SUBSYSTEM_ID << 16) |
                     (WIFI_SUBSYSTEM_ID << 8) | ZIGBEE_SUBSYSTEM_ID;

        if (ol_ath_coex_ver_cfg(scn, &coex_ss_id) == EOK ) {
            scn->coex_ss_priority = coex_ss_id;
        }
    }

#ifdef ATH_SUPPORT_WAPI
    if((scn->target_type == TARGET_TYPE_QCA9984)
        || (scn->target_type == TARGET_TYPE_QCA9888)
        || (scn->target_type == TARGET_TYPE_IPQ4019)){
        A_UINT8 bit_loc;
        ATH_VAP_ID_BIT_LOC(bit_loc);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] WAPI MBSSID %d \n",__func__,__LINE__,bit_loc);
        ol_ath_pdev_set_param(scn, wmi_pdev_param_wapi_mbssid_offset, bit_loc, 0);
    }
#endif

#if OL_ATH_SMART_LOGGING
    if (wmi_service_enabled(scn->wmi_handle, wmi_service_smart_logging_support)) {
        smart_log_init(scn);
    }
#endif /* OL_ATH_SMART_LOGGING */

    return 0;
}

int
ol_ath_service_ready_ex_event(ol_scn_t scn_handle, uint8_t *evt_buf, uint16_t len)
{
  struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)scn_handle;
  scn->wmi_service_ready = TRUE;

  qdf_print("Recieved ex event\n");
  return wmi_unified_init_cmd_send(scn->wmi_handle, &scn->wlan_resource_config,
      scn->num_mem_chunks, scn->mem_chunks);
}

int
ol_ath_ready_event(ol_scn_t scn_handle, uint8_t *ev, uint16_t len)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)scn_handle;
	struct wmi_host_fw_abi_ver fw_ver;

	if(wmi_extract_fw_abi_version(scn->wmi_handle, ev, &fw_ver) ==
				QDF_STATUS_SUCCESS) {
		scn->version.wlan_ver = fw_ver.sw_version;
		scn->version.abi_ver = fw_ver.abi_version;
	}

    if (wmi_check_and_update_fw_version(scn->wmi_handle, ev) < 0) {
        qdf_print("Version mismatch with FW\n");
        return -1;
    }
    /*
     * Indicate to the waiting thread that the ready
     * event was received
     */
    scn->wmi_ready = TRUE;

    scn->wlan_init_status = wmi_ready_extract_init_status(scn->wmi_handle, ev);
    /* copy the mac addr */
    wmi_ready_extract_mac_addr(scn->wmi_handle, ev, scn->sc_ic.ic_myaddr);
    wmi_ready_extract_mac_addr(scn->wmi_handle, ev, scn->sc_ic.ic_my_hwaddr);

    __ol_ath_wmi_ready_event(scn);

    return 0;
}

/*
 *  WMI API for setting fw hang.
 *  type parameter can be one of the 6 values defined in
 *  wmi_unified.h enumerated as RECOVERY_SIM_TYPE
 */
int
ol_ath_set_fw_hang(struct ol_ath_softc_net80211 *scn, u_int32_t delay_time_ms)
{
    struct crash_inject param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.delay_time_ms = delay_time_ms;

    return wmi_crash_inject(scn->wmi_handle, &param);
}

#if QCA_AIRTIME_FAIRNESS
/*
 *  WMI API for ATF
 */
int
ol_ath_set_bwf(struct ieee80211com *ic)
{
	int i = 0, retval = 0;
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
	struct set_bwf_params *param;

	param = (struct set_bwf_params *)
		kmalloc((sizeof(struct set_bwf_params) +
		((ATF_ACTIVED_MAX_CLIENTS - 1) * sizeof(bwf_peer_info))), GFP_ATOMIC);

	if (!param) {
	    qdf_print("%s: Unable to allocate temporary copy of mu report event,"
				" Dropping mu report event\n", __func__);
	    return -EINVAL;
	}

	param->num_peers = ic->wmi_bwfreq.num_peers;
	for (i =0; i< ic->wmi_bwfreq.num_peers;i++) {
	    OS_MEMCPY((void *)&(param->peer_info[i]),(void *)&(ic->wmi_bwfreq.bwf_peer_info[i]),sizeof(bwf_peer_info));
	}

	retval = wmi_unified_set_bwf_cmd_send(scn->wmi_handle, param);
	kfree(param);
	return retval;
}

int
ol_ath_set_atf(struct ieee80211com *ic)
{
    int i = 0, retval = 0;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct set_atf_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.num_peers = ic->wmi_atfreq.num_peers;
    for (i =0; i< ic->wmi_atfreq.num_peers;i++)
    {
        OS_MEMCPY((void *)&(param.peer_info[i]),(void *)&(ic->wmi_atfreq.atf_peer_info[i]),sizeof(atf_peer_info));
    }
/*    printk("wmi_unified_pdev_set_atf peer_num=%d \n",cmd->num_peers); */
    if (!ic->ic_atf_tput_based){
        retval = wmi_unified_set_atf_cmd_send(scn->wmi_handle, &param);
    }
    return retval;
}

int
ol_ath_send_atf_peer_request(struct ieee80211com *ic)
{
	struct atf_peer_request_params atf_peer_req;
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
	int i,retval = 0;

	qdf_mem_set(&atf_peer_req, sizeof(atf_peer_req), 0);
	atf_peer_req.num_peers = ic->wmi_atf_peer_req.num_peers;

	for (i = 0; i < ic->wmi_atf_peer_req.num_peers;i++)
	{
		OS_MEMCPY((void *)&(atf_peer_req.peer_ext_info[i]),(void *)&(ic->wmi_atf_peer_req.atf_peer_ext_info[i])
				,sizeof(atf_peer_ext_info));
	}
    	if(!ic->ic_atf_tput_based){
		retval = wmi_send_atf_peer_request_cmd(scn->wmi_handle, &atf_peer_req);
	}
	return retval;
}

int
ol_ath_set_atf_grouping(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
	struct atf_grouping_params group_params;
	int i,retval = 0;

	qdf_mem_set(&group_params, sizeof(group_params), 0);
	group_params.num_groups = ic->wmi_atf_group_req.num_groups;

	for (i =0; i< ic->wmi_atf_group_req.num_groups;i++)
	{
		OS_MEMCPY((void *)&(group_params.group_info[i]),(void *)&(ic->wmi_atf_group_req.atf_group_info[i]),sizeof
					(atf_group_info));
	}
    if(!ic->ic_atf_tput_based){
		retval = wmi_send_set_atf_grouping_cmd(scn->wmi_handle, &group_params);
	}
	return retval;
}
#endif


#if ATH_SUPPORT_FIPS

/*
 *  WMI API for FIPS
 */
int
ol_ath_pdev_fips(struct ol_ath_softc_net80211 *scn,
                      u_int8_t *key,
                      u_int32_t key_len,
                      u_int8_t *data,
                      u_int32_t data_len,
                      u_int32_t mode,
                      u_int32_t op)
{
    int retval = 0;
    struct fips_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.key_len = key_len;
    param.data_len = data_len;
    param.op = op;
    param.key = key;
    param.data = data;
    param.mode = mode;

    retval = wmi_unified_pdev_fips_cmd_send(scn->wmi_handle, &param);
    return retval;
}

static int
ol_ath_fips_event_handler(ol_scn_t scn, u_int8_t *evt_buf, u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    u_int32_t output_len, data_len, *data;

    /* Set this flag to notify fips_event had occured */
    qdf_atomic_inc(&(ic->ic_fips_event));

    wmi_extract_fips_event_data(scn->wmi_handle, evt_buf, &data_len, &data);
	output_len = sizeof(struct ath_fips_output) + data_len;

    /* To pass the output data to application */
    ic->ic_output_fips = (struct ath_fips_output *) OS_MALLOC(scn->sc_osdev, output_len, GFP_KERNEL);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s ic->ic_output_fips %p\n", __func__, ic->ic_output_fips);
    wmi_extract_fips_event_error_status(scn->wmi_handle, evt_buf, &ic->ic_output_fips->error_status);
    ic->ic_output_fips->data_len = data_len;
    print_hex_dump(KERN_DEBUG, "\t Handler Data: ", DUMP_PREFIX_NONE, 16, 1, data, data_len, true);
    OS_MEMCPY(ic->ic_output_fips->data, data, data_len);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s error_status %x data_len %x\n",
            __func__, ic->ic_output_fips->error_status, data_len);
    print_hex_dump(KERN_DEBUG, "Cipher text: ", DUMP_PREFIX_NONE, 16, 1,
               data, data_len, true);
    return 0;
}
#endif

/* This API is not called. We should probably deprecate and remove this*/
int
ol_ath_pdev_set_channel(struct ol_ath_softc_net80211 *scn,
                           struct ieee80211_channel *chan, u_int32_t freq)
{
    struct channel_param param;
    u_int32_t chan_mode;

    qdf_mem_set(&param, sizeof(param), 0);
    param.mhz = freq;

    chan_mode = ieee80211_chan2mode(chan);
    param.phy_mode = ol_get_phymode_info(chan_mode);
    param.cfreq1 = 0;
    param.cfreq2 = 0;
    if((chan_mode == IEEE80211_MODE_11AC_VHT80) ||(chan_mode == IEEE80211_MODE_11AC_VHT160) || (chan_mode == IEEE80211_MODE_11AC_VHT80_80)) {
            if (chan->ic_ieee < 20)
                param.cfreq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                                                          chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_2GHZ);
            else
                param.cfreq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                                                          chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_5GHZ);
        if (chan_mode == IEEE80211_MODE_11AC_VHT80_80 || chan_mode == IEEE80211_MODE_11AC_VHT160)
            param.cfreq2 = ieee80211_ieee2mhz(&scn->sc_ic,
                    chan->ic_vhtop_ch_freq_seg2, IEEE80211_CHAN_5GHZ);

    } else if((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) || (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
        (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS)) {
            param.cfreq1 = freq + 10;
    } else if((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) || (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
        (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS)) {
            param.cfreq1 = freq - 10;
    } else {
            param.cfreq1 = freq;
    }

    if (IEEE80211_IS_CHAN_DFS(chan))
        param.dfs_set = TRUE;

    if (chan_mode == IEEE80211_MODE_11AC_VHT80_80) {
        if (IEEE80211_IS_CHAN_DFS_CFREQ2(chan)) {
            param.dfs_set_cfreq2 = TRUE;
        }
    }

    if (IEEE80211_IS_CHAN_HALF(chan))
        param.half_rate = TRUE;
    if (IEEE80211_IS_CHAN_QUARTER(chan))
        param.quarter_rate = TRUE;

    param.minpower = chan->ic_minpower;
    param.maxpower = chan->ic_maxpower;
    param.maxregpower = chan->ic_maxregpower;
    param.antennamax = chan->ic_antennamax;
    param.reg_class_id = chan->ic_regClassId;

    return wmi_unified_set_chan_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_pdev_set_ht_ie(struct ol_ath_softc_net80211 *scn, u_int32_t ie_len, u_int8_t *ie_data)
{
    struct ht_ie_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ie_len = ie_len;
    param.ie_data = ie_data;
    return wmi_unified_set_ht_ie_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_pdev_set_vht_ie(struct ol_ath_softc_net80211 *scn, u_int32_t ie_len, u_int8_t *ie_data)
{
    struct vht_ie_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ie_len = ie_len;
    param.ie_data = ie_data;
    return wmi_unified_set_vht_ie_cmd_send(scn->wmi_handle, &param);
}

#define MAX_IE_SIZE 512

#define MAX_HT_IE_LEN 32
#define MAX_VHT_IE_LEN 32
void ol_ath_set_ht_vht_ies(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn->set_ht_vht_ies) {
        u_int8_t *buf=qdf_mem_malloc(MAX_IE_SIZE);
        u_int8_t *buf_end;
        if (buf) {
            buf_end = ieee80211_add_htcap(buf, vap->iv_bss,IEEE80211_FC0_SUBTYPE_PROBE_REQ);
            if ((buf_end - buf ) <= MAX_HT_IE_LEN ) {
                ol_ath_pdev_set_ht_ie(scn,buf_end-buf, buf);
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: HT IE length %d is more than expected\n",__func__, (buf_end-buf));
            }
            buf_end = ieee80211_add_vhtcap(buf, vap->iv_bss,ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_REQ, NULL, NULL);
            if ((buf_end - buf ) <= MAX_VHT_IE_LEN ) {
                ol_ath_pdev_set_vht_ie(scn,buf_end-buf,buf);
            } else {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: VHT IE length %d is more than expected\n",__func__, (buf_end-buf));
            }
            scn->set_ht_vht_ies = 1;
            qdf_mem_free(buf);
        }
    }
}

struct ieee80211_channel *
ol_ath_find_full_channel(struct ieee80211com *ic, u_int32_t freq)
{
    struct ieee80211_channel    *c;
    c = NULL;
#define IEEE80211_2GHZ_FREQUENCY_THRESHOLD    3000            // in kHz
    if (freq < IEEE80211_2GHZ_FREQUENCY_THRESHOLD) { /* 2GHZ channel */
        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT20)) {
            c = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_11NG_HT20);
        }

        if (c == NULL) {
            c = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_G);
        }


        if (c == NULL) {
            c = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_PUREG);
        }

        if (c == NULL) {
            c = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_B);
        }
    } else {
        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT20)) {
            c = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_11NA_HT20);
        }

        if (c == NULL) {
            u_int32_t halfquarter = ic->ic_chanbwflag & (IEEE80211_CHAN_HALF | IEEE80211_CHAN_QUARTER);
            c = ieee80211_find_channel(ic, freq, 0, IEEE80211_CHAN_A | halfquarter);
        }
    }
    return c;
#undef IEEE80211_2GHZ_FREQUENCY_THRESHOLD
}

/* Offload Interface functions for UMAC */
static int
ol_ath_init(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static int
ol_ath_reset_start(struct ieee80211com *ic, bool no_flush)
{
    /* TBD */
    return 0;
}

static int
ol_ath_reset_end(struct ieee80211com *ic, bool no_flush)
{
    /* TBD */
    return 0;
}

static void
ol_set_beacon_interval(struct ieee80211com *ic)
{
    /* TBD */
    return;
}

static int
ol_ath_reset(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static void
ol_ath_updateslot(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wlan_if_t vap = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    int slottime;

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap != NULL) {
            avn = OL_ATH_VAP_NET80211(vap);
            break;
        }
    }
    if (NULL == avn) {
        return;
    }

    slottime = (IEEE80211_IS_SHSLOT_ENABLED(ic)) ?  9 : 20;

    if(IEEE80211_IS_SHSLOT_ENABLED(ic)) {
        ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
            wmi_vdev_param_slot_time, WMI_HOST_VDEV_SLOT_TIME_SHORT);
    } else {
        ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
            wmi_vdev_param_slot_time, WMI_HOST_VDEV_SLOT_TIME_LONG);
    }
    return;
}

int
wmi_txpower_beacon(struct ol_ath_softc_net80211 *scn, u_int8_t tx_power,
                        struct ol_txrx_pdev_t *pdev)
{
    int retval = -1, ret = 0;
    struct ol_txrx_vdev_t *vdev;

    TAILQ_FOREACH(vdev, &pdev->vdev_list, vdev_list_elem) {
        if (vdev != NULL) {
            ret = ol_ath_wmi_send_vdev_param(scn, vdev->vdev_id,
                                                  wmi_vdev_param_mgmt_tx_power, tx_power);
            if (ret != EOK)
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "set TX Power for beacon wmi_failed: wmi_status %d vap-id %u\n", ret,vdev->vdev_id);
            else
                retval = EOK;
        }
    }
    return retval;
}
int
wmi_txpower_vap_beacon(struct ol_ath_softc_net80211 *scn,u_int8_t tx_power,
        struct ol_txrx_vdev_t *vdev)
{
    int retval = EOK;

    if (vdev != NULL) {
        retval = ol_ath_wmi_send_vdev_param(scn, vdev->vdev_id,
                wmi_vdev_param_mgmt_tx_power, tx_power);
        if (retval != EOK){
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "set TX Power for beacon wmi_failed: wmi_status %d vap-id %u\n", retval,vdev->vdev_id);
            retval = -1;
        }
    }
    return retval;
}

#if ATH_SUPPORT_FIPS
void fips_data_dump(void *arg)
{
    struct ath_fips_cmd *afb = (struct ath_fips_cmd *)arg;
    int i;
    u_int8_t *ptr = (u_int8_t *) afb->data;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n ********Dumping FIPS structure********\n");
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n FIPS command: %d", afb->fips_cmd);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Key Length: %d", afb->key_len);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n Data Length: %d", afb->data_len);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n************* KEY ************\n");
    for (i=0; i < afb->key_len; i++)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x ",afb->key[i]);
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n************* DATA ***********\n");

    for (i=0; i < (afb->data_len); i++)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x ", *(ptr + i));
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n************* IV  ***********\n");

    for (i=0; i < 16; i++)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%02x ", afb->iv[i]);
    }
}

static int ol_ath_fips_test(struct ieee80211com *ic, struct ath_fips_cmd *fips_buf)
{
    int retval = 0;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    fips_data_dump(fips_buf);

    if (fips_buf->key_len <= MAX_KEY_LEN_FIPS)  {
            retval = ol_ath_pdev_fips(scn, fips_buf->key,
                            fips_buf->key_len, (u_int8_t *)fips_buf->data,
                            fips_buf->data_len, fips_buf->mode, fips_buf->fips_cmd);
        } else retval = -EINVAL;

    if (-EINVAL == retval) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s:%d Data Length invalid: must be multiple"
            "of 16 bytes and < 1500 bytes \n", __func__, __LINE__);
        retval = -EFAULT;
    }
    return retval;
}
#endif

static int
ol_ath_wmm_update(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct wmm_update_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.wmep_array = (struct wmi_host_wmeParams *)ic->ic_wme.wme_chanParams.cap_wmeParams;
    wmi_unified_wmm_update_cmd_send(scn->wmi_handle, &param);
    return 0;
}


static u_int32_t
ol_ath_txq_depth(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static u_int32_t
ol_ath_txq_depth_ac(struct ieee80211com *ic,int ac)
{
    /* TBD */
    return 0;
}

/*
 * Function to set 802.11 protection mode
 */
static void
ol_ath_update_protmode(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wlan_if_t vap = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    A_UINT8  protmode = IEEE80211_PROT_NONE;

    if (IEEE80211_IS_PROTECTION_ENABLED(ic)) {
        /* Protection flag is set. Use ic_protmode */
        protmode = ic->ic_protmode;
    }

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap != NULL) {
	    avn = OL_ATH_VAP_NET80211(vap);
	    if (NULL != avn)
                ol_ath_wmi_send_vdev_param(scn, avn->av_if_id,
                                wmi_vdev_param_protection_mode, protmode);
        }
    }
}

static void
ol_net80211_chwidth_change(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);

    if(ol_ath_node_set_param(scn,ni->ni_macaddr,WMI_HOST_PEER_CHWIDTH,
            ni->ni_chwidth,avn->av_if_id)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to change peer bandwidth\n", __func__);
    }
}

static void
ol_ath_ar900b_fw_test(struct ieee80211com *ic, u_int32_t arg, u_int32_t value )
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct set_fwtest_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.arg = arg;
    param.value = value;

    wmi_unified_vdev_set_fwtest_param_cmd_send(scn->wmi_handle, &param);

    return;
}

static void
ol_net80211_nss_change(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    struct ieee80211vap *vap = ni->ni_vap;

    /* TODO: Enable code to send differnt NSS values per BW even for cases when EXT NSS is not enabled */
    if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH160) && vap->iv_ext_nss_capable && ni->ni_ext_nss_support) {
        if (vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT160) {
            if(ol_ath_node_set_param(scn,ni->ni_macaddr, WMI_HOST_PEER_NSS_VHT160,
                 IEEE80211_GET_BW_NSS_FWCONF_160(ni->ni_bwnss_map) + 1, avn->av_if_id)) {
                qdf_print("%s:Unable to change peer Nss\n", __func__);
            }
        } else if (vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT80_80) {
            if(ol_ath_node_set_param(scn,ni->ni_macaddr, WMI_HOST_PEER_NSS_VHT80_80,
                 IEEE80211_GET_BW_NSS_FWCONF_80_80(ni->ni_bwnss_map) + 1, avn->av_if_id)) {
                qdf_print("%s:Unable to change peer Nss\n", __func__);
           }
        }
    }

    if(ol_ath_node_set_param(scn,ni->ni_macaddr, WMI_HOST_PEER_NSS,
            ni->ni_streams, avn->av_if_id)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to change peer Nss\n", __func__);
    }

/*
 * Beeliner change
 */
#if 0
    ol_ath_node_update(ni);
#endif
}

    static void
ol_net80211_set_sta_fixed_rate(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);

    if(ol_ath_node_set_param(scn,ni->ni_macaddr,WMI_HOST_PEER_PARAM_FIXED_RATE,
                ni->ni_fixed_rate,avn->av_if_id)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to set peer to fixed rate\n", __func__);
    }
}
struct ol_vap_mode_count {
    u_int32_t non_monitor_mode_vap_cnt;
    u_int32_t monitor_mode_vap_cnt;
};

static void check_monitor_only_vapmode(void *arg, struct ieee80211vap *vap)
{
    struct ol_vap_mode_count *mode_cnt = (struct ol_vap_mode_count *)arg;

    if (IEEE80211_M_MONITOR != vap->iv_opmode) {
        mode_cnt->non_monitor_mode_vap_cnt++;
    } else if (IEEE80211_M_MONITOR == vap->iv_opmode) {
        mode_cnt->monitor_mode_vap_cnt++;
    }

    return;
}


static void get_monitor_mode_vap(void *arg, struct ieee80211vap *vap)
{
    ieee80211_vap_t *ppvap=(ieee80211_vap_t *)arg;

    if (IEEE80211_M_MONITOR == vap->iv_opmode) {
        *ppvap = vap;
    }

    return;
}

static void get_ap_mode_vap(void *arg, struct ieee80211vap *vap)
{
    ieee80211_vap_t *ppvap=(ieee80211_vap_t *)arg;

    if (IEEE80211_M_HOSTAP == vap->iv_opmode) {
        *ppvap = vap;
    }

    return;
}

static void get_sta_mode_vap(void *arg, struct ieee80211vap *vap)
{
    ieee80211_vap_t *ppvap=(ieee80211_vap_t *)arg;

    if (IEEE80211_M_STA == vap->iv_opmode) {
        *ppvap = vap;
    }

    return;
}

static void ol_vap_instant_restart_iter_func(void *arg, struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211_channel *chan = (struct ieee80211_channel *)arg;
    bool disable_hw_ack = false;


    avn = OL_ATH_VAP_NET80211(vap);
    scn = avn->av_sc;

    if (ol_ath_vdev_restart_send(scn,
                avn->av_if_id, chan,
                chan->ic_freq,
                disable_hw_ack)) {
        qdf_print("ERROR : %s[%d] Unable to bring up the interface for ath_dev.\n", __func__, __LINE__);
    } else {
        avn->av_restart_in_progress = TRUE;
    }
    avn->av_ol_resmgr_wait = TRUE;
    return;
}

static void ol_vap_restart_iter_func(void *arg, struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211_channel *chan = (struct ieee80211_channel *)arg;
    int waitcnt = 0;
    bool disable_hw_ack = false;

    if ( (IEEE80211_M_HOSTAP == vap->iv_opmode) ||
         (IEEE80211_M_MONITOR == vap->iv_opmode) ) {
        avn = OL_ATH_VAP_NET80211(vap);

        if (!ieee80211_vap_dfswait_is_set(vap) &&
                (!(ieee80211_vap_ready_is_set(vap) ||
                               avn->av_ol_resmgr_wait) ||
                qdf_atomic_read(&(vap->init_in_progress)))) {
            /* Channel change request to FW is not needed, if vap is not ready */
            return;
        }

        scn = avn->av_sc;

        disable_hw_ack = (IEEE80211_IS_CHAN_DFS(chan) ||
            ((IEEE80211_IS_CHAN_11AC_VHT80_80(chan) ||
              IEEE80211_IS_CHAN_11AC_VHT160(chan)) &&
              IEEE80211_IS_CHAN_DFS_CFREQ2(chan)));

        /* If we set av_ol_resmgr_wait and init_in_progress after sending
         * VDEV_RESTART, FW could send VDEV_START_RESP before we get a chance
         * to actually update av_ol_resmgr_wait and init_in_progress.
         * So we set them in advance
         */
        avn->av_ol_resmgr_wait = TRUE;
        if (!vap->iv_special_vap_mode) {
            if ( (!ieee80211_vap_dfswait_is_set(vap) || !IEEE80211_IS_CHAN_DFS(chan)) &&
                  !in_interrupt() ) {
                qdf_atomic_set(&(vap->init_in_progress), 1);
            }
        }

        qdf_atomic_set(&(vap->iv_is_start_sent), 1);

        if (ol_ath_vdev_restart_send(scn,
            avn->av_if_id, chan,
            chan->ic_freq,
            disable_hw_ack)) {
            QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR : %s[%d] Unable to bring up the interface for ath_dev.\n", __func__, __LINE__);
            qdf_atomic_set(&(vap->iv_is_start_sent), 0);
        } else {
            avn->av_restart_in_progress = TRUE;
        }
        if (!vap->iv_special_vap_mode) {
            /* For special mode vap there no need to wait as only one VAP will be active
             * avoiding delay here.
             */
            if(ieee80211_vap_dfswait_is_set(vap) && IEEE80211_IS_CHAN_DFS(chan)){
                /*
                   Fix CSA channel change from DFS=>DFS takes too long time issue.
                   vap->init_in_progress will be changed to FALSE,only in ol_ath_vap_up() in this case.
                   So, if vap is in dfswait and new channel's DFS channel,
                   ol_ath_vap_up() won't be called until CAC timer timeout,
                   skip this waiting delay in this case.
                */
            }else{
                if(!in_interrupt()) /* Allow only non-interrupt context */
                {
                    /* Wait for previous vdev_start and vdev_stop command to complete */
                    while(qdf_atomic_read(&(vap->init_in_progress)) && (waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT)) {
                        schedule_timeout_interruptible(OSIF_STOP_VAP_TIMEOUT);
                        waitcnt++;
                    }
                }// in_interrupt()
            }
        }
    }
    return;
}

static void
ol_ath_net80211_enable_radar(struct ieee80211com *ic, int no_cac)
{
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
static void
ol_ath_net80211_enable_sta_radar(struct ieee80211com *ic, int no_cac)
{
    ol_if_dfs_configure(ic);
}
#endif

static int
ol_ath_set_channel(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211_channel *chan;
    u_int32_t freq;
    ieee80211_vap_t vap = NULL;

    chan = ieee80211_get_current_channel(ic);

    freq = ieee80211_chan2freq(ic, chan);
    if (!freq) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ERROR : INVALID Freq \n");
        return 0;
    }

    /* update max channel power to max regpower of current channel */
    ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);

    /* Update the channel for monitor mode path */
    ol_txrx_set_curchan(scn->pdev_txrx_handle, freq);

    wlan_iterate_vap_list(ic, get_sta_mode_vap ,(void *)&vap );
    if (vap) {
        /* There is a active STA mode vap.
         * for STA mode channel change will happen through resmgr channnel change
         */
         return -1;
    }
    else {
        /* Call a new channel change WMI cmd for all VAPs in AP/monitor mode.  */
        /****************************************
        FIXME: better way is to restart all VAPs in osif layer resmgr_vap_start() path,
        with parameter restart=1, e.g. wlan_mlme_start_bss(vap,1)
        ****************************************/
        if((ic->ic_prevchan) && (chan != ic->ic_prevchan)){
            /*If different channel, need to restart all VAPs.
              If channel numbers are same, but channel ic_flags are different,
              we still consider this as 'different' channel */
            wlan_iterate_vap_list(ic, ol_vap_restart_iter_func, (void *)chan);
        }
    }
#if ATH_SUPPORT_DFS
    /*
        EV129487 :
        We should not call ol_if_dfs_configure here.
        This will be done when FW indicates that channel
        switch request is complete. This is handled in
        ol_vdev_wmi_event_handler when firmware sends
        ol_vdev_start_resp_ev
    */

    //ol_if_dfs_configure(ic);
#endif
    /* once the channel change is complete, turn on the dcs,
     * use the same state as what the current enabled state of the dcs. Also
     * set the run state accordingly.
     */
    (void)ol_ath_pdev_set_param(scn, wmi_pdev_param_dcs, scn->scn_dcs.dcs_enable&0x0f, 0);

    (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) ? (OL_ATH_DCS_SET_RUNSTATE(scn->scn_dcs.dcs_enable)) :
                            (OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable));

    return 0;
}

static void
ol_ath_log_text(struct ieee80211com *ic, char *text)
{
    /* This function needs to be called from interrupt context. Temporaily disabling this as this
     * is getting called from different contexts */
    return;
#if 0
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

#ifndef REMOVE_PKT_LOG
    scn->pl_dev->pl_funcs->pktlog_text(scn,text);
#endif
#endif
}

static void
ol_ath_log_text_bh(struct ieee80211com *ic, char *text)
{
    /* This function needs to be called only from bottom half context */
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

#ifndef REMOVE_PKT_LOG
    if(scn->pl_dev)
        scn->pl_dev->pl_funcs->pktlog_text(scn,text);
#endif
    return;
}

static void
ol_ath_pwrsave_set_state(struct ieee80211com *ic, IEEE80211_PWRSAVE_STATE newstate)
{
    /* The host does not manage the HW power state with offload FW. This function
     * exists solely for completeness.
     */
}

u_int
ol_ath_mhz2ieee(struct ieee80211com *ic, u_int freq, u_int flags)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)
struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* TBD */
     /* FIXME: This change has been added for testing
      * This below code block is copied from direct attach architecture
      * Some of the code has been disabled because those APIs and Macros yet
      * to be defined
      */

#if 0
    if (flags & CHANNEL_2GHZ) { /* 2GHz band */
        if (freq == 2484)
            return 14;
        if (freq < 2484)
            return (freq - 2407) / 5;
        else
            return 15 + ((freq - 2512) / 20);
    } else if (flags & CHANNEL_5GHZ) {/* 5Ghz band */
     /*   if (ath_hal_ispublicsafetysku(ah) &&
            IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) +
                (((freq % 5) == 2) ? 5 : 0) - 49400) / 5;
        } else */if ((flags & CHANNEL_A) && (freq <= 5000)) {
            return (freq - 4000) / 5;
        } else {
            return (freq - 5000) / 5;
        }
    } else
#endif
    {            /* either, guess */
        if (freq == 2484)
            return 14;
        if (freq < 2484)
            return (freq - 2407) / 5;
        if (freq < 5000) {
            if (ol_regdmn_ispublicsafetysku(scn->ol_regdmn_handle)
                && IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
                return ((freq * 10) +
                    (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
            } else if (freq > 4900) {
                return (freq - 4000) / 5;
            } else {
                return 15 + ((freq - 2512) / 20);
            }
        }
        return (freq - 5000) / 5;
    }
}


static int16_t ol_ath_get_noisefloor (struct ieee80211com *ic, struct ieee80211_channel *chan,
                                        int wait_time)
{
    /* TBD */
    return 0;
}
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static  void ol_ath_net80211_check_buffull_condition(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
	if(scn->buff_thresh.free_descs <= scn->buff_thresh.ald_free_buf_lvl)
	{
			scn->buff_thresh.ald_buffull_wrn = 0;
	}
	else
    {
			scn->buff_thresh.ald_buffull_wrn = 1;
    }
}
#endif
static int16_t ol_ath_net80211_get_cur_chan_noisefloor(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return scn->chan_nf;
}

static void
ol_ath_get_chainnoisefloor(struct ieee80211com *ic, struct ieee80211_channel *chan, int16_t *nfBuf)
{
    /* TBD */
    return;
}

static void
ol_ath_set_ant_switch_tbl(struct ieee80211com *ic, u_int32_t antCtrlCommon1, u_int32_t antCtrlCommon2)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ant_switch_tbl_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ant_ctrl_common1 = antCtrlCommon1;
    param.ant_ctrl_common2 = antCtrlCommon2;

    if(wmi_unified_set_ant_switch_tbl_cmd_send(scn->wmi_handle, &param)) {
        return;
    }

    return;

}

/*
 * Override the rate power table in EEPROM
 */
static void
ol_ath_set_ratepwr_table(struct ieee80211com *ic, u_int8_t *ratepwr_tbl, u_int16_t ratepwr_len)
{

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ratepwr_table_params param;

    if (!ratepwr_tbl)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ratepwr_tbl = ratepwr_tbl;
    param.ratepwr_len = ratepwr_len;

    if(wmi_unified_set_ratepwr_table_cmd_send(scn->wmi_handle, &param)) {
        return;
    }

    return;
}

/*
 * Get the rate power table in EEPROM
 */
static void
ol_ath_get_ratepwr_table(struct ieee80211com *ic)
{

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if(wmi_unified_get_ratepwr_table_cmd_send(scn->wmi_handle)) {
        return;
    }

    return;
}

/*
 * EEPROM rate power table operations
 */
static void
ol_ath_ratepwr_table_ops(struct ieee80211com *ic, u_int8_t ops,
                        u_int8_t *ratepwr_tbl, u_int16_t ratepwr_len)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (scn->target_type != TARGET_TYPE_AR9888) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"rate power table override is only supported for AR98XX\n");
        return;
    }

    if (ops == WMI_HOST_RATEPWR_TABLE_OPS_SET) {
        QC98XX_EEPROM_RATETBL eep_tbl;

        memset((u_int8_t *)&eep_tbl, 0, sizeof(QC98XX_EEPROM_RATETBL));
        /* convert user format to eeprom format */
        ol_if_ratepwr_usr_to_eeprom((u_int8_t *)&eep_tbl, sizeof(QC98XX_EEPROM_RATETBL),
                                    ratepwr_tbl, ratepwr_len);

        ol_ath_set_ratepwr_table(ic, (u_int8_t*)&eep_tbl, sizeof(QC98XX_EEPROM_RATETBL));
    } else if (ops == WMI_HOST_RATEPWR_TABLE_OPS_GET) {
        ol_ath_get_ratepwr_table(ic);
    } else
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Unknown ratepwr table ops %d\n", ops);

    return;
}

/*
 * The format of the CTL table defined as below
 */
#if 0
typedef struct {
    A_UINT8  ctl_edges[WHAL_NUM_BAND_EDGES_2G];
} __packed CAL_CTL_DATA_2G;

typedef struct {
    A_UINT8  ctl_edges[WHAL_NUM_BAND_EDGES_5G];
} __packed CAL_CTL_DATA_5G;

typedef struct {
    A_UINT8                       ctlFreqbin2G[WHAL_NUM_CTLS_2G][WHAL_NUM_BAND_EDGES_2G];
    CAL_CTL_DATA_2G               ctlData2G[WHAL_NUM_CTLS_2G];
    A_UINT8                       ctlFreqbin5G[WHAL_NUM_CTLS_5G][WHAL_NUM_BAND_EDGES_5G];
    CAL_CTL_DATA_5G               ctlData5G[WHAL_NUM_CTLS_5G];
} __packed CAL_INFO;
#endif

static void
ol_ath_set_ctl_table(struct ieee80211com *ic, u_int8_t *ctl_array, u_int16_t ctl_len)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ctl_table_params param;

    if (!ctl_array)
        return;

    qdf_mem_set(&param, sizeof(param), 0);

    qdf_mem_copy(&param.ctl_band, ctl_array, sizeof(uint32_t));
    param.ctl_array = ctl_array + sizeof(uint32_t);
    param.ctl_cmd_len = ctl_len;
    param.target_type = scn->target_type;
    if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
        param.is_2g = TRUE;
    } else {
        param.is_2g = FALSE;
    }

    if(wmi_unified_set_ctl_table_cmd_send(scn->wmi_handle, &param)) {
        return;
    }

    return;
}

static void
ol_ath_set_mimogain_table(struct ieee80211com *ic, u_int8_t *array_gain,
                            u_int16_t tbl_len, bool multichain_gain_bypass)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct mimogain_table_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    if (!array_gain)
        return;

    param.array_gain = array_gain;
    param.tbl_len = tbl_len;
    param.multichain_gain_bypass = multichain_gain_bypass;

    if(wmi_unified_set_mimogain_table_cmd_send(scn->wmi_handle, &param)) {
        return;
    }

    return;
}

/*
 * Override the rate power and chain mask used in the FW
 * @param ratepwr_chain_tbl : input ratepwr table, each element in u_int32_t format
 * @param num_rate          : 12 rates for CCK/OFDM, 48 rates for HT20/40, 90 rates for VHT rate
 * @param pream_type        : 0=CCK/OFDM, 1=HT20/40, 2=VHT rate
 * @param ops               : 0=disable, 1=enable
 */
static void
ol_ath_set_ratepwr_chainmsk(struct ieee80211com *ic, u_int32_t *ratepwr_chain_tbl,
                            u_int16_t num_rate, u_int8_t pream_type, u_int8_t ops)
{
#define RC_CCK_OFDM_RATES       0
#define RC_HT_RATES             1
#define RC_VHT_RATES            2
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ratepwr_chainmsk_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ratepwr_chain_tbl = ratepwr_chain_tbl;
    param.num_rate = num_rate;
    param.ops = ops;
    param.pream_type = pream_type;

    if (pream_type == RC_CCK_OFDM_RATES &&
        num_rate != HT_20_RATE_TABLE_INDEX - CCK_RATE_TABLE_INDEX) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK/OFDM rate num should be %d\n", HT_20_RATE_TABLE_INDEX - CCK_RATE_TABLE_INDEX);
        return;
    }

    if (pream_type == RC_HT_RATES &&
        num_rate != VHT_20_RATE_TABLE_INDEX - HT_20_RATE_TABLE_INDEX) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT20/40 rate num should be %d\n", VHT_20_RATE_TABLE_INDEX - HT_20_RATE_TABLE_INDEX);
        return;
    }

    if (pream_type == RC_VHT_RATES &&
        num_rate != RATE_TABLE_SIZE - VHT_20_RATE_TABLE_INDEX) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT rate num should be %d\n", RATE_TABLE_SIZE - VHT_20_RATE_TABLE_INDEX);
        return;
    }

    wmi_unified_set_ratepwr_chainmsk_cmd_send(scn->wmi_handle, &param);
    return;
}

void
ol_ath_dump_target(struct ol_ath_softc_net80211 *scn)
{
    char fw_dump_file[128]={0};

    get_next_dump_file_index(scn, fw_dump_file, sizeof(fw_dump_file));
    qdf_print("** STARTING RUNTIME DUMP TARGET TO %s\n", fw_dump_file);
    fw_get_core_dump(scn, fw_dump_file, 1);
    qdf_print("*** RUNTIME DUMP TARGET COMPLETE ***\n");
}

/* per node tpc control */
static void
ol_ath_set_node_tpc(struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t tpc)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn;

    avn = (ni!=NULL)? OL_ATH_VAP_NET80211(ni->ni_vap):NULL;

    if (!avn)
        return;

    if(ol_ath_node_set_param(scn, ni->ni_macaddr,
            WMI_HOST_PEER_USE_FIXED_PWR, tpc, avn->av_if_id)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:Unable to send fixed pwr\n", __func__);
    }
}

static void
ol_ath_set_rxfilter(struct ieee80211com *ic, u_int32_t filter)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (ol_ath_pdev_set_param(scn,
                wmi_pdev_param_rx_filter, filter, 0) != EOK)
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error setting rxfilter 0x%08x\n", filter);
}

void
ol_ath_setTxPowerLimit(struct ieee80211com *ic, u_int32_t limit, u_int16_t tpcInDb, u_int32_t is2GHz)
{
    int retval = 0;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int16_t cur_tx_power = ieee80211com_get_txpowerlimit(ic);

    if (cur_tx_power != limit) {
        /* Update max tx power only if the current max tx power is different */
        if (limit > scn->max_tx_power) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Tx power value is greater than supported max tx power %d, Limiting to default Max\n",
                    scn->max_tx_power);
		limit = scn->max_tx_power;
        }
        if (is2GHz) {
            retval = ol_ath_pdev_set_param(scn,
                wmi_pdev_param_txpower_limit2g, limit, 0);
        } else {
            retval = ol_ath_pdev_set_param(scn,
                wmi_pdev_param_txpower_limit5g, limit, 0);
        }
        if (retval == EOK) {
            /* Update the ic_txpowlimit */
            if (is2GHz) {
                scn->txpowlimit2G = limit;
            } else {
                scn->txpowlimit5G = limit;
            }
            if ((is2GHz && IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) ||
                (!is2GHz && !IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)))
            {
                ieee80211com_set_txpowerlimit(ic, (u_int16_t) (limit));
            }
        }
    }
}

static u_int8_t
ol_ath_get_common_power(struct ieee80211com *ic, struct ieee80211_channel *chan)
{
    /* TBD */
    return 0;
}

static u_int32_t
ol_ath_getTSF32(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static int
ol_ath_getrmcounters(struct ieee80211com *ic, struct ieee80211_mib_cycle_cnts *pCnts)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* "ic->ic_mib_cycle_cnts" gets updated during a periodic stats event */
    pCnts->tx_frame_count = scn->mib_cycle_cnts.tx_frame_count;
    pCnts->rx_frame_count = scn->mib_cycle_cnts.rx_frame_count;
    pCnts->rx_clear_count = scn->mib_cycle_cnts.rx_clear_count;
    pCnts->cycle_count = scn->mib_cycle_cnts.cycle_count;

    /* "is_rx_active" and "is_tx_active" not being used, but for safety, set it to 0 */
    pCnts->is_rx_active = 0;
    pCnts->is_tx_active = 0;

    return 0;
}

static u_int32_t
ol_ath_wpsPushButton(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static void
ol_ath_clear_phystats(struct ieee80211com *ic)
{
    /* TBD */
    return;
}

static int
ol_ath_set_macaddr(struct ieee80211com *ic, u_int8_t *macaddr)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct macaddr_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.macaddr = macaddr;

    if(wmi_unified_set_macaddr_cmd_send(scn->wmi_handle, &param)) {
        return -1;
    }

    return 0;
}

static int
ol_ath_set_chain_mask(struct ieee80211com *ic, ieee80211_device_param type, u_int32_t mask)
{
    /* TBD */
    return 0;
}

static u_int32_t
ol_ath_getmfpsupport(struct ieee80211com *ic)
{
    return IEEE80211_MFP_HW_CRYPTO;
}

static void
ol_ath_setmfpQos(struct ieee80211com *ic, u_int32_t dot11w)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_pdev_set_param(scn,
                               wmi_pdev_param_pmf_qos, dot11w, 0);
    return;
}

static u_int64_t
ol_ath_get_tx_hw_retries(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

static u_int64_t
ol_ath_get_tx_hw_success(struct ieee80211com *ic)
{
    /* TBD */
    return 0;
}

/* Update peer rate table */
static void
ol_ath_rate_node_update(struct ieee80211com *ic, struct ieee80211_node *ni,
                                   int isnew)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* reuse the ASSOC_CMDID to perform the dynamic rate setting */
    ol_ath_send_peer_assoc(scn, ic, ni, isnew);
}

static int
ol_ath_debug_print_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
#ifdef BIG_ENDIAN_HOST
       char dbgbuf[500] = {0};
       memcpy(dbgbuf, data, datalen);
       SWAPME(dbgbuf, datalen);
       QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "FIRMWARE:%s \n",dbgbuf);
       return 0;
#else
       QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "FIRMWARE:%s \n",data);
       return 0;
#endif
}

static void
ol_ath_set_config(struct ieee80211vap* vap)
{
    /* Currently Not used for Offload */
}

static void
ol_ath_set_safemode(struct ieee80211vap* vap, int val)
{
    ol_txrx_vdev_handle vdev = (ol_txrx_vdev_handle) vap->iv_txrx_handle;
    if (vdev) {
        ol_txrx_set_safemode(vdev, val);
    }
    return;
}

static void
ol_ath_set_privacy_filters(struct ieee80211vap* vap)
{
    ol_txrx_vdev_handle vdev = (ol_txrx_vdev_handle) vap->iv_txrx_handle;
    if (vdev) {
        ol_txrx_set_privacy_filters(vdev, vap->iv_privacy_filters, vap->iv_num_privacy_filters);
    }
    return;
}

static void
ol_ath_set_drop_unenc(struct ieee80211vap* vap, int val)
{
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    ol_txrx_vdev_handle vdev = NULL;

    if (vap == NULL) return;

    ic = vap->iv_ic;
    avn = OL_ATH_VAP_NET80211(vap);
    scn = OL_ATH_SOFTC_NET80211(ic);

    vdev = (ol_txrx_vdev_handle) vap->iv_txrx_handle;
    if (vdev) {
        ol_txrx_set_drop_unenc(vdev, val);
    }

    ol_ath_wmi_send_vdev_param(scn, avn->av_if_id, wmi_vdev_param_drop_unencry, val);

    return;
}

static void
ol_ath_scan_start(struct ieee80211com *ic)
{
#ifdef DEPRECATED_QCA
    /*
     * this command was added to support host scan egine which is deprecated.
     * now  the scan engine is in FW and host directly isssues a scan request
     * to perform scan and provide results back to host
     */
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    wmi_unified_pdev_scan_start_cmd_send(scn->wmi_handle);
#endif
}

static void
ol_ath_scan_end(struct ieee80211com *ic)
{
#ifdef DEPRECATED_QCA
    /*
     * this command was added to support host scan egine which is deprecated.
     * now  the scan engine is in FW and host directly isssues a scan request
     * to perform scan and provide results back to host
     */
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_unified_pdev_scan_end_cmd_send(scn->wmi_handle);
#endif
}

#if ATH_SUPPORT_IQUE
void
ol_ath_set_acparams(struct ieee80211com *ic, u_int8_t ac, u_int8_t use_rts,
                          u_int8_t aggrsize_scaling, u_int32_t min_kbps)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct acparams_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.ac = ac;
    param.aggrsize_scaling = aggrsize_scaling;

    wmi_unified_set_acparams_cmd_send(scn->wmi_handle, &param);
    return;
}

void
ol_ath_set_rtparams(struct ieee80211com *ic, u_int8_t ac, u_int8_t perThresh,
                          u_int8_t probeInterval)
{
    /* TBD */
    return;
}

void
ol_ath_get_iqueconfig(struct ieee80211com *ic)
{
    /* TBD */
    return;
}

void
ol_ath_set_hbrparams(struct ieee80211vap *iv, u_int8_t ac, u_int8_t enable, u_int8_t per)
{
    /* TBD */
    return;
}
#endif /*ATH_SUPPORT_IQUE*/

/*
 * Disable the dcs im when the intereference is detected too many times. for
 * thresholds check umac
 */
static void
ol_ath_disable_dcsim(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* clear the run state, only when cwim is not set */
    if (!(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & ATH_CAP_DCS_CWIM)) {
        OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable);
    }

    OL_ATH_DCS_DISABLE(scn->scn_dcs.dcs_enable, ATH_CAP_DCS_WLANIM);

    /* send target to disable and then disable in host */
    ol_ath_pdev_set_param(scn, wmi_pdev_param_dcs, scn->scn_dcs.dcs_enable, 0);
}

static void
ol_ath_enable_dcsim(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* Enable wlanim for DCS */
    OL_ATH_DCS_ENABLE(scn->scn_dcs.dcs_enable, ATH_CAP_DCS_WLANIM);

    /* send target to enable and then enable in host */
    ol_ath_pdev_set_param(scn, wmi_pdev_param_dcs, scn->scn_dcs.dcs_enable, 0);
}

/*
 * Disable the dcs cw when the intereference is detected too many times. for
 * thresholds check umac
 */
static void
ol_ath_disable_dcscw(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int8_t dcs_enable = scn->scn_dcs.dcs_enable;

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS: %s dcs state %x \n",__func__,scn->scn_dcs.dcs_enable);

    if (!(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & ATH_CAP_DCS_CWIM)) {
       return;
    }

    OL_ATH_DCS_DISABLE(scn->scn_dcs.dcs_enable, ATH_CAP_DCS_CWIM);
    /* send target to disable and then disable in host */
    if (ol_ath_pdev_set_param(scn, wmi_pdev_param_dcs,
                                         scn->scn_dcs.dcs_enable, 0) != EOK) {
        OL_ATH_DCS_ENABLE(scn->scn_dcs.dcs_enable, dcs_enable);
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Error in disabling CWIM\n");
    }
}
#ifdef ATH_SUPPORT_TxBF

static int
ol_ath_net80211_txbf_alloc_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return 0;
}

static void
ol_ath_net80211_txbf_set_key(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return;
}

static void
ol_ath_net80211_init_sw_cv_timeout(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return;
}

static int
ol_ath_set_txbfcapability(struct ieee80211com *ic)
{
    return 0;
}

#ifdef TXBF_DEBUG
static void
ol_ath_net80211_txbf_check_cvcache(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    return 0;
}
#endif

static void
ol_ath_net80211_CSI_Frame_send(struct ieee80211_node *ni,
						u_int8_t	*CSI_buf,
                        u_int16_t	buf_len,
						u_int8_t    *mimo_control)
{
    return;
}

static void
ol_ath_net80211_v_cv_send(struct ieee80211_node *ni,
                       u_int8_t *data_buf,
                       u_int16_t buf_len)
{
    return;
}
static void
ol_ath_net80211_txbf_stats_rpt_inc(struct ieee80211com *ic,
                                struct ieee80211_node *ni)
{
    return;
}
static void
ol_ath_net80211_txbf_set_rpt_received(struct ieee80211com *ic,
                                struct ieee80211_node *ni)
{
    return;
}
#endif

static bool
ol_ath_net80211_is_mode_offload(struct ieee80211com *ic)
{
    /*
     * If this function executes, it is offload mode
     */
    return TRUE;
}

static bool
ol_ath_net80211_is_macreq_enabled(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return ((scn->macreq_enabled == 1) ? TRUE : FALSE);
}

static u_int32_t
ol_ath_net80211_get_mac_prealloc_idmask(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return scn->sc_prealloc_idmask;
}

static int
ol_ath_net80211_tr69_get_fail_retrans_cnt(struct ieee80211vap *vap, u_int32_t *failretranscnt)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    *failretranscnt = avn->vdev_extd_stats.mpdu_fail_retry;

    return 0;
}

static int
ol_ath_net80211_tr69_get_retry_cnt(struct ieee80211vap *vap, u_int32_t *retranscnt)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    *retranscnt = avn->vdev_extd_stats.mpdu_suc_retry;

    return 0;
}

static int
ol_ath_net80211_tr69_get_mul_retry_cnt(struct ieee80211vap *vap, u_int32_t *retranscnt)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    *retranscnt = avn->vdev_extd_stats.mpdu_suc_multitry;

    return 0;
}

static int
ol_ath_net80211_tr69_get_ack_fail_cnt(struct ieee80211vap *vap, u_int32_t *ackfailcnt)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    *ackfailcnt = avn->vdev_extd_stats.ppdu_noack;

    return 0;
}

static int
ol_ath_net80211_tr69_get_aggr_pkt_cnt(struct ieee80211vap *vap, u_int32_t *aggrpkts)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    *aggrpkts = avn->vdev_extd_stats.ppdu_aggr_cnt;

    return 0;
}

static int
ol_ath_net80211_tr69_get_sta_bytes_sent(struct ieee80211vap *vap, u_int32_t *bytessent, u_int8_t *dstmac)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;

    ni = ieee80211_find_node(&ic->ic_sta, dstmac);
    if (ni == NULL) {
        return -ENOENT;
    }
    *bytessent = ni->ni_stats.ns_dot11_tx_bytes;

    ieee80211_free_node(ni);
    return 0;
}

static int
ol_ath_net80211_tr69_get_sta_bytes_rcvd(struct ieee80211vap *vap, u_int32_t *bytesrcvd, u_int8_t *dstmac)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;

    ni = ieee80211_find_node(&ic->ic_sta, dstmac);
    if (ni == NULL) {
        return -ENOENT;
    }
    *bytesrcvd = ni->ni_stats.ns_dot11_rx_bytes;
    ieee80211_free_node(ni);
    return 0;
}

static int
ol_ath_net80211_tr69_get_chan_util(struct ieee80211vap *vap, u_int32_t *chanutil)
{
    return 0;
}

static int
ol_ath_net80211_tr69_get_retrans_cnt(struct ieee80211vap *vap, u_int32_t *retranscnt)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    *retranscnt = avn->vdev_extd_stats.mpdu_sw_requed;

    return 0;
}

static int
ol_ath_net80211_tr69_process_request(struct ieee80211vap *vap, int cmdid, void * arg1, void *arg2)
{
    //	struct ieee80211com *ic = vap->iv_ic;

	switch(cmdid){
#if 0
        case IEEE80211_TR069_GET_PLCP_ERR_CNT:
			ol_ath_net80211_tr69_get_plcp_err_cnt(dev, arg1);
            break;
        case IEEE80211_TR069_GET_FCS_ERR_CNT:
			ol_ath_net80211_tr69_get_fcs_err_cnt(dev, arg1);
            break;
        case IEEE80211_TR069_GET_PKTS_OTHER_RCVD:
			ol_ath_net80211_tr69_get_pkts_other_rcvd(dev, req);
            break;
#endif
        case IEEE80211_TR069_GET_FAIL_RETRANS_CNT:
			ol_ath_net80211_tr69_get_fail_retrans_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_RETRY_CNT:
			ol_ath_net80211_tr69_get_retry_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_MUL_RETRY_CNT:
			ol_ath_net80211_tr69_get_mul_retry_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_ACK_FAIL_CNT:
			ol_ath_net80211_tr69_get_ack_fail_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_AGGR_PKT_CNT:
			ol_ath_net80211_tr69_get_aggr_pkt_cnt(vap, arg1);
            break;
        case IEEE80211_TR069_GET_STA_BYTES_SENT:
			ol_ath_net80211_tr69_get_sta_bytes_sent(vap, arg1, arg2);
            break;
        case IEEE80211_TR069_GET_STA_BYTES_RCVD:
			ol_ath_net80211_tr69_get_sta_bytes_rcvd(vap, arg1, arg2);
            break;
#if 0
        case IEEE80211_TR069_GET_DATA_SENT_ACK:
			ol_ath_net80211_tr69_get_data_sent_ack(dev, arg1);
            break;
        case IEEE80211_TR069_GET_DATA_SENT_NOACK:
			ol_ath_net80211_tr69_get_data_sent_noack(dev, req);
            break;
#endif
        case IEEE80211_TR069_GET_CHAN_UTIL:
			ol_ath_net80211_tr69_get_chan_util(vap, arg1);
            break;
        case IEEE80211_TR069_GET_RETRANS_CNT:
			ol_ath_net80211_tr69_get_retrans_cnt(vap, arg1);
            break;
        default:
			break;
    }

    return 0;
}

int
ol_ath_net80211_get_vap_stats(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    if (NULL == avn) {
        return -1;
    }
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "-----VAP Stats------\n");
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ppdu_aggr         = %d\n", avn->vdev_extd_stats.ppdu_aggr_cnt);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ppdu_nonaggr      = %d\n", avn->vdev_extd_stats.ppdu_nonaggr_cnt);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "noack             = %d\n", avn->vdev_extd_stats.ppdu_noack);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mpdu_queued       = %d\n", avn->vdev_extd_stats.mpdu_queued);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mpdu_requeued     = %d\n", avn->vdev_extd_stats.mpdu_sw_requed);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mpdu_suc_retry    = %d\n", avn->vdev_extd_stats.mpdu_suc_retry);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mpdu_suc_multitry = %d\n", avn->vdev_extd_stats.mpdu_suc_multitry);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "mpdu_fail_retry   = %d\n", avn->vdev_extd_stats.mpdu_fail_retry);
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "-----VAP Stats------\n");
    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");

    return 0;
}

/*
 * Register the DCS functionality
 * As such this is very small function and is not going to contain too many
 * functions, right now continuing in the same file. Once it grows bigger,
 * move to different file.
 *
 *  # register event handler to receive non-wireless lan interference event
 *  # register event handler to receive the extended stats that are meant for
 *    receiving the timed extra stats
 *        - right now this is not implemented and would implement
 *          as we go with second implementation
 *  # initialize the initial enabled state
 *  # initialize the host data strucutres that are meant for handling
 *    the wireless lan interference.
 *          - right now these variables would not be used
 *  # Keep the initialized state as disabled, and enable
 *    when first channel gets activated.
 *  # Keep the status as disabled until completely qualified
 */
void
ol_ath_dcs_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    /* Register WMI event handlers */
	scn->scn_dcs.dcs_enable                 = 0;
    OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable);
	scn->scn_dcs.phy_err_penalty            = DCS_PHYERR_PENALTY;
	scn->scn_dcs.phy_err_threshold          = DCS_PHYERR_THRESHOLD ;
	scn->scn_dcs.radar_err_threshold        = DCS_RADARERR_THRESHOLD;
	scn->scn_dcs.coch_intr_thresh           = DCS_COCH_INTR_THRESHOLD ;
	scn->scn_dcs.user_max_cu                = DCS_USER_MAX_CU; /* tx_cu + rx_cu */
	scn->scn_dcs.intr_detection_threshold   = DCS_INTR_DETECTION_THR;
	scn->scn_dcs.intr_detection_window      = DCS_SAMPLE_SIZE;
	scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt = 0;
	scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt = 0;
    scn->scn_dcs.dcs_debug                  = DCS_DEBUG_DISABLE;

    wmi_unified_register_event_handler(scn->wmi_handle, wmi_dcs_interference_event_id,
                                            ol_ath_dcs_interference_handler, WMI_RX_UMAC_CTX);
    return;
}

#if ATH_OL_FAST_CHANNEL_RESET_WAR
#define DISABLE_FAST_CHANNEL_RESET 1
     /*WAR for EV#117307, MSDU_DONE is not set for data packet,
      to fix this issue, fast channel change is disabled for x86 platform*/
void ol_ath_fast_chan_change(struct ol_ath_softc_net80211 *scn)
{
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Disabling fast channel reset \n");
    if(ol_ath_pdev_set_param(scn,
                       wmi_pdev_param_fast_channel_reset,
                       DISABLE_FAST_CHANNEL_RESET, 0)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Failed to disable fast channel reset \n");
    }
}
#endif

#define CTS2SELF_DTIM_ENABLE 0x1
#define CTS2SELF_DTIM_DISABLE 0x0
void
ol_ath_set_vap_cts2self_prot_dtim_bcn(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;

    if (vap == NULL) return;

    ic = vap->iv_ic;
    avn = OL_ATH_VAP_NET80211(vap);
    scn = OL_ATH_SOFTC_NET80211(ic);

    /* Enable CTS-to-self */
    if (vap->iv_cts2self_prot_dtim_bcn) {
         ol_ath_wmi_send_vdev_param( scn,avn->av_if_id,
                     wmi_vdev_param_dtim_enable_cts, CTS2SELF_DTIM_ENABLE);
    } else {
         ol_ath_wmi_send_vdev_param( scn,avn->av_if_id,
                     wmi_vdev_param_dtim_enable_cts, CTS2SELF_DTIM_DISABLE);
     }
}
#undef CTS2SELF_DTIM_ENABLE
#undef CTS2SELF_DTIM_DISABLE

/* The below mapping is according the doc, which is as follows,

DSCP        TID     AC
000000      0       WME_AC_BE
001000      1       WME_AC_BK
010000      1       WME_AC_BK
011000      0       WME_AC_BE
100000      5       WME_AC_VI
101000      5       WME_AC_VI
110000      6       WME_AC_VO
111000      6       WME_AC_VO

*/

int
ol_ath_set_vap_dscp_tid_map(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct vap_dscp_tid_map_params param;

    qdf_mem_set(&param, sizeof(param), 0);
#if ATH_SUPPORT_DSCP_OVERRIDE
    if(vap->iv_override_dscp) {
        /* Send updated copy of the TID-Map */
        param.dscp_to_tid_map = vap->iv_dscp_tid_map;
    } else if(ic->ic_override_dscp) {
        param.dscp_to_tid_map = ic->ic_dscp_tid_map;
    }
    else {
        param.dscp_to_tid_map = dscp_tid_map;
    }
#endif
    param.vdev_id = avn->av_if_id;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_vdev_set_dscp_tid_map(vap->iv_txrx_handle, param.dscp_to_tid_map);
#endif
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Setting dscp for vap id: %d\n", param.vdev_id);

    return wmi_unified_set_vap_dscp_tid_map_cmd_send(scn->wmi_handle, &param);
}

#if ATH_SUPPORT_DSCP_OVERRIDE
void
ol_ath_set_hmmc_tid(struct ieee80211com *ic , u_int32_t tid)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* If Override is disabled: send default TID  else passed the intended tid value */
    if(!ic->ic_override_hmmc_dscp) {
        tid = 0xFF;                 //TBD::Replace it with proper macro
    }
    ol_ath_pdev_set_param(scn, wmi_pdev_set_mcast_to_ucast_tid, tid, 0);

    ic->ic_dscp_hmmc_tid = tid;

    return;
}

u_int32_t
ol_ath_get_hmmc_tid(struct ieee80211com *ic)
{
    return ic->ic_dscp_hmmc_tid;
}

void
ol_ath_set_hmmc_dscp_override(struct ieee80211com *ic , u_int32_t val)
{

    /* If nothing to do just return */
    if(ic->ic_override_hmmc_dscp == val) {
	return;
    }
    ic->ic_override_hmmc_dscp = !!val;

    /* Inform target as well */
    ol_ath_set_hmmc_tid(ic, ic->ic_dscp_hmmc_tid);
    return;
}

u_int32_t
ol_ath_get_hmmc_dscp_override(struct ieee80211com *ic)
{
    return ic->ic_override_hmmc_dscp;
}

#endif

static void
ol_update_txpow_vdev(ol_txrx_vdev_handle vdev, uint8_t subtype,uint8_t transmit_power)
{
    vdev->txpow_mgt_frm[(subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)] = transmit_power;
    return;
}

void ol_wlan_txpow_mgmt(struct ieee80211vap *vap,u_int8_t subtype)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int retval = EOK;
    if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
        retval = wmi_txpower_vap_beacon(scn,vap->iv_txpow_mgt_frm[(subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)], vap->iv_txrx_handle);
    }
    if (retval == EOK){
        ol_update_txpow_vdev(vap->iv_txrx_handle, subtype,vap->iv_txpow_mgt_frm[(subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)]);
    }
return;
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static void ol_ieee80211_me_hifitbl_update_target(wlan_if_t vap)
{
    int i, j;
    int group_count = 0, node_count = 0;
    int action = IGMP_ACTION_ADD_MEMBER;
    int wildcard = IGMP_WILDCARD_SINGLE;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    struct ieee80211_me_hifi_table *ht = &vap->iv_me->me_hifi_table;
    struct ieee80211_me_hifi_node *node;
    char *grpaddr;
    int grpaddrlen;

    group_count = vap->iv_me->me_hifi_table.entry_cnt;

    if( group_count != 0)
    {
        vap->iv_ic->ic_mcast_group_update(vap->iv_ic, IGMP_ACTION_DELETE_MEMBER, IGMP_WILDCARD_ALL, NULL, 0, NULL, 0, 0, NULL, NULL, vap->iv_unit);
        if(group_count > scn->wlan_resource_config.num_mcast_groups)
            group_count = scn->wlan_resource_config.num_mcast_groups;

        for(i = 0; i < group_count ; i++) {
            node_count = ht->entry[i].node_cnt;

            if(node_count > scn->wlan_resource_config.num_mcast_table_elems)
                node_count = scn->wlan_resource_config.num_mcast_table_elems;

            grpaddr = (int8_t *)(&ht->entry[i].group.u);
            grpaddrlen = (ht->entry[i].group.pro == ETHERTYPE_IP) ? IGMP_IP_ADDR_LENGTH : 16;
            for(j=0; j< node_count; j++){
                node = &ht->entry[i].nodes[j];
                vap->iv_ic->ic_mcast_group_update(vap->iv_ic, action, wildcard,
                        grpaddr, grpaddrlen, node->mac, node->filter_mode, node->nsrcs, node->srcs, NULL, vap->iv_unit);
            }
        }
    } else {
        vap->iv_ic->ic_mcast_group_update(vap->iv_ic, IGMP_ACTION_DELETE_MEMBER, IGMP_WILDCARD_ALL, NULL, 0, NULL, 0, 0, NULL, NULL, vap->iv_unit);
    }
}
#endif

#if ATH_PROXY_NOACK_WAR

static OS_TIMER_FUNC(ol_proxy_ast_reserve_timeout)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (ic->proxy_ast_reserve_wait.blocking) {
         if(qdf_atomic_dec_and_test(&ic->ic_ast_reserve_event)) {
            ic->ic_ast_reserve_status=-2;
            qdf_semaphore_release(&(ic->proxy_ast_reserve_wait.sem_ptr));
         }
    }
}

static int
ol_ath_pdev_proxy_ast_reserve(struct ol_ath_softc_net80211 *scn, u_int8_t *macaddr)
{
    struct proxy_ast_reserve_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.macaddr = macaddr;

    return wmi_unified_proxy_ast_reserve_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_pdev_proxy_ast_reserve_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    uint32_t result;
    struct ieee80211com *ic = &scn->sc_ic;

    if (wmi_extract_pdev_reserve_ast_ev_param(scn->wmi_handle, data, &result)) {
        return -1;
    }

    OS_CANCEL_TIMER(&(ic->ic_ast_reserve_timer));

    if (ic->proxy_ast_reserve_wait.blocking) {
        if(qdf_atomic_dec_and_test(&ic->ic_ast_reserve_event)) {
           ic->ic_ast_reserve_status = result;
           QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Status received from FW: func: %s ,event->result=%d, ic->ic_ast_reserve_status=%d \n",__func__,result, ic->ic_ast_reserve_status);
           qdf_semaphore_release(&(ic->proxy_ast_reserve_wait.sem_ptr));
        }
    }
    return 0;
}

int32_t ol_ioctl_get_proxy_noack_war(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int war_enable;

    if(scn->sc_proxy_noack_war) {
        war_enable = 1;
    } else {
        war_enable = 0;
    }

    return _copy_to_user((caddr_t)param , &war_enable, sizeof(war_enable));
}

int32_t ol_ioctl_reserve_proxy_macaddr(struct ol_ath_softc_net80211 *scn, caddr_t *param)
{
    struct ieee80211com *ic = &scn->sc_ic;
    int error = 0;
    struct {
        u8 addr[6];
        int status;
    } psta_addr_reserve;

    if(!scn->sc_proxy_noack_war) {
        return -1;
    }

    ic->ic_ast_reserve_status= -1;

    if(OS_CANCEL_TIMER(&(ic->ic_ast_reserve_timer))) {
        error = _copy_to_user((caddr_t)param , &psta_addr_reserve, sizeof(psta_addr_reserve));
        return error;
    }

    error = __xcopy_from_user(&psta_addr_reserve, param, sizeof(psta_addr_reserve));

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s mac_addr =%s  \n",__func__,ether_sprintf(psta_addr_reserve.addr));

    qdf_atomic_init(&(ic->ic_ast_reserve_event));

    qdf_atomic_inc(&(ic->ic_ast_reserve_event));

    OS_SET_TIMER(&ic->ic_ast_reserve_timer, TARGET_AST_RESERVE_TIMEOUT *2000);

    ol_ath_pdev_proxy_ast_reserve(scn, psta_addr_reserve.addr);

    if (ic->proxy_ast_reserve_wait.blocking) {
       qdf_semaphore_acquire(&(ic->proxy_ast_reserve_wait.sem_ptr));
    }

    psta_addr_reserve.status = ic->ic_ast_reserve_status;

    error = _copy_to_user((caddr_t)param , &psta_addr_reserve, sizeof(psta_addr_reserve));

    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s  status=%d \n",__func__,psta_addr_reserve.status);

    return error;
}
#endif

#if ATH_SUPPORT_WRAP && DBDC_REPEATER_SUPPORT
int32_t ol_ioctl_get_primary_radio(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int primary_radio;
    struct ieee80211com *ic = &scn->sc_ic;

    if(ic->ic_primary_radio) {
        primary_radio = 1;
    } else {
        primary_radio = 0;
    }

    return _copy_to_user((caddr_t)param , &primary_radio, sizeof(primary_radio));
}

int32_t ol_ioctl_get_mpsta_mac_addr(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *mpsta_vap;

    if (ic->ic_mpsta_vap == NULL)
    {
        return -EFAULT;
    }
    mpsta_vap = ic->ic_mpsta_vap;

    return _copy_to_user((caddr_t)param , mpsta_vap->iv_myaddr, IEEE80211_ADDR_LEN);
}

void ol_ioctl_disassoc_clients(struct ol_ath_softc_net80211 *scn)
{
	struct ieee80211com *ic = &scn->sc_ic;
	struct ieee80211vap           *tmp_vap;
	struct ieee80211com           *tmp_ic;
	int i=0;

	for (i=0; i < MAX_RADIO_CNT; i++) {
		tmp_ic = ic->ic_global_list->global_ic[i];
		if (tmp_ic) {
			TAILQ_FOREACH(tmp_vap, &tmp_ic->ic_vaps, iv_next) {
				if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) && ieee80211_vap_ready_is_set(tmp_vap)) {
					wlan_iterate_station_list(tmp_vap, sta_disassoc, NULL);
				}
			}
		}
	}
}

int32_t ol_ioctl_get_force_client_mcast(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int force_client_mcast;
    struct ieee80211com *ic = &scn->sc_ic;

    if(ic->ic_global_list->force_client_mcast_traffic) {
        force_client_mcast = 1;
    } else {
        force_client_mcast = 0;
    }

    return _copy_to_user((caddr_t)param , &force_client_mcast, sizeof(force_client_mcast));
}

int32_t ol_ioctl_get_max_priority_radio(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    char wifi_iface[IFNAMSIZ];
    struct ieee80211com *ic = &scn->sc_ic;
    struct global_ic_list   *glist = ic->ic_global_list;
    struct ieee80211vap           *max_priority_stavap_up;
    struct ieee80211com *max_priority_ic;
    struct net_device *n_dev;

    memset(&wifi_iface[0], 0, sizeof(wifi_iface));
    GLOBAL_IC_LOCK(glist);
    max_priority_stavap_up = glist->max_priority_stavap_up;
    GLOBAL_IC_UNLOCK(glist);
    if (max_priority_stavap_up && ieee80211_vap_ready_is_set(max_priority_stavap_up)) {
	max_priority_ic = max_priority_stavap_up->iv_ic;
	n_dev = max_priority_ic->ic_osdev->netdev;
	OS_MEMCPY(wifi_iface, n_dev->name, sizeof(wifi_iface));
	qdf_print("max priority radio:%s\n",wifi_iface);
    }
    return _copy_to_user((caddr_t)param , wifi_iface, IFNAMSIZ);
}
#endif

void ol_ioctl_iface_mgr_status(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    struct ieee80211com *ic = &scn->sc_ic;
    u_int8_t *iface_mgr_up = (u_int8_t *)param;

    GLOBAL_IC_LOCK(ic->ic_global_list);
    if ((*iface_mgr_up) == 1) {
        ic->ic_global_list->iface_mgr_up = 1;
        qdf_print("setting iface_mgr_up to 1\n");
    } else {
        ic->ic_global_list->iface_mgr_up = 0;
        qdf_print("setting iface_mgr_up to 0\n");
    }
    GLOBAL_IC_UNLOCK(ic->ic_global_list);
}

u_int8_t ol_ioctl_get_stavap_connection(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    u_int8_t stavap_up;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap           *stavap = ic->ic_sta_vap;
    osif_dev *osifp;

    osifp = (osif_dev *)wlan_vap_get_registered_handle(stavap);
    if(osifp == NULL) {
        return -EINVAL;
    }
    if (osifp->is_up) {
        stavap_up = 1;
    } else {
        stavap_up = 0;
    }

    return _copy_to_user(param , &stavap_up, sizeof(stavap_up));
}

u_int16_t ol_ioctl_get_disconnection_timeout(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    u_int16_t timeout;
    struct ieee80211com *ic = &scn->sc_ic;
    u_int16_t disconnect_timeout = ic->ic_global_list->disconnect_timeout;
    u_int16_t reconfiguration_timeout = ic->ic_global_list->reconfiguration_timeout;

    if (disconnect_timeout >= reconfiguration_timeout) {
        timeout = disconnect_timeout;
        qdf_print("disconnect_timeout:%d\n",disconnect_timeout);
    } else {
        timeout = reconfiguration_timeout;
        qdf_print("reconfiguration_timeout:%d\n",reconfiguration_timeout);
    }

    return _copy_to_user(param , &timeout, sizeof(timeout));
}

int32_t ol_ioctl_get_preferred_uplink(struct ol_ath_softc_net80211 *scn, caddr_t param)
{
    int preferredUplink;
    struct ieee80211com *ic = &scn->sc_ic;

    if(ic->ic_preferredUplink) {
        preferredUplink = 1;
    } else {
        preferredUplink = 0;
    }

    return _copy_to_user((caddr_t)param , &preferredUplink, sizeof(preferredUplink));
}

#if MESH_MODE_SUPPORT
extern void ieee80211_check_timeout_mesh_peer(void *arg, wlan_if_t vaphandle);
#endif
/*
 * Per-ieee80211com timer callback.
 * used for checking any timeouts in the
 * COM device.
 */
static OS_TIMER_FUNC(ol_ath_timeout)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    ieee80211_session_timeout(&ic->ic_sta);
    ieee80211_vap_mlme_inact_erp_timeout(ic);

#if MESH_MODE_SUPPORT
    /* check & delete timed out mesh peers */
    wlan_iterate_vap_list(ic, ieee80211_check_timeout_mesh_peer, NULL);
#endif

    OS_SET_TIMER(&ic->ic_inact_timer, IEEE80211_SESSION_WAIT*1000);
}

static int
ol_ath_set_mgmt_retry_limit(struct ieee80211com *ic , u_int8_t limit)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int ret = 0;

    QDF_PRINT_INFO(ic ->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d Set mgmt retry limit to %d\n",__FUNCTION__,__LINE__,limit);
    ret = ol_ath_pdev_set_param(scn, wmi_pdev_param_mgmt_retry_limit, limit, 0);
    if(ret){
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s:%d Set mgmt retry limit failed!\n",__FUNCTION__,__LINE__));
        return ret;
    }
    scn->scn_mgmt_retry_limit = limit;
    return 0;
}

static u_int8_t
ol_ath_get_mgmt_retry_limit(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    return (scn->scn_mgmt_retry_limit);
}

static bool
ol_ath_support_phy_mode(struct ieee80211com *ic, enum ieee80211_phymode mode)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int8_t cur_rx_mask = ieee80211com_get_rx_chainmask(ic);
    u_int8_t cur_tx_mask = ieee80211com_get_tx_chainmask(ic);
    bool rx_mask_is_valid = false;

    if ((mode == IEEE80211_MODE_11AC_VHT160 ||
        mode == IEEE80211_MODE_11AC_VHT80_80)) {

        if ( scn->target_type == TARGET_TYPE_QCA9984) {
            /* 160 and 80+80 modes are allowed only with the following chainmasks
             * in Cascade */
            switch (cur_rx_mask) {
                case 0x5:
                case 0x6:
                /*
                 * We permit 0x7 for special case of 3x3 80MHz and 1x1 160MHz in
                 * QCA9984
                 */
                case 0x7:
                case 0x9:
                case 0xa:
                case 0xc:
                case 0xf:
                    rx_mask_is_valid = true;
                    break;
                default:
                    return false;
            }

            switch (cur_tx_mask) {
                case 0x5:
                case 0x6:
                /*
                 * We permit 0x7 for special case of 3x3 80MHz and 1x1 160MHz in
                 * QCA9984
                 */
                case 0x7:
                case 0x9:
                case 0xa:
                case 0xc:
                case 0xf:
                    if(rx_mask_is_valid)
                        return true;
                    else
                        return false;
                default:
                    return false;
            }
        } else if ( scn->target_type == TARGET_TYPE_QCA9888 ) {
            switch (cur_rx_mask) {
                /* 160 and 80+80 modes are allowed only with the following chainmasks
                 * in Besra */
                 case 0x3:
                    return true;
                default:
                    return false;
            }
        }
    }
    /* Currently this function is used to validate 160MHz vs. chainmask
     * compatibility in Cascade. Return true for other cases */
    return true;
}

static int
ol_ath_get_bw_nss_mapping(struct ieee80211vap *vap, struct ieee80211_bwnss_map *nssmap, u_int8_t chainmask)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int error = 0;

    if ((vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT160 ||
        vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT80_80)) {

        if (scn->target_type == TARGET_TYPE_QCA9984) {
	        /* 160 and 80+80 modes are allowed only with the following chainmasks
	         * in Cascade */
            switch (chainmask) {
                case 0x5:
                case 0x6:
                /*
                 * We permit 0x7 for special case of 3x3 80MHz and 1x1 160MHz in
                 * QCA9984
                 */
                case 0x7:
                case 0x9:
                case 0xa:
                case 0xc:
                    nssmap->bw_nss_160 = IEEE80211_BW_NSS_MAP_1x1;
                    break;
                case 0xf:
                    nssmap->bw_nss_160 = IEEE80211_BW_NSS_MAP_2x2;
                    break;
                default:
                    error = -EINVAL;
            }
	} else if (scn->target_type == TARGET_TYPE_QCA9888) {
            /* 160 and 80+80 modes are allowed only with the following chainmasks
             * in Besra */
            switch (chainmask) {
                case 0x3:
                    nssmap->bw_nss_160 = IEEE80211_BW_NSS_MAP_1x1;
                    break;
                default:
                    error = -EINVAL;
            }
	} else {
            /* Currently this function is used to find valid 160MHz NSS map in
             * Cascade and Besra based on the rx_chainmask configured. Return error for
             * other cases */
            error = -EINVAL;
        }
    } else {
        /* Currently this function is used to find valid 160MHz NSS map in
         * Cascade and Besra based on the rx_chainmask configured. Return error for
         * other cases */
        error = -EINVAL;
    }

    if ((error != -EINVAL) && (vap->iv_nss != 0)) {
        nssmap->bw_nss_160 = QDF_MIN(vap->iv_nss - 1, nssmap->bw_nss_160);
        if ((nssmap->bw_nss_160) == (vap->iv_nss - 1)) {
            nssmap->flag |= IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW;
        }
    }
    return error;
}


int
ol_ath_dev_attach(struct ol_ath_softc_net80211 *scn,
                   IEEE80211_REG_PARAMETERS *ieee80211_conf_parm)
{
    struct ieee80211com *ic = &scn->sc_ic;
    int error = 0;
    spin_lock_init(&ic->ic_lock);
    spin_lock_init(&ic->ic_main_sta_lock);
    spin_lock_init(&ic->ic_addba_lock);
    IEEE80211_STATE_LOCK_INIT(ic);
    spin_lock_init(&ic->ic_beacon_alloc_lock);

    spin_lock_init(&ic->ic_state_check_lock);

    /* attach channel width management */
    error = ol_ath_cwm_attach(scn);
    if (error) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : ol_ath_cwm_attach failed \n", __func__);
        return error;
    }

    /* XXX not right but it's not used anywhere important */
    ieee80211com_set_phytype(ic, IEEE80211_T_OFDM);

    /*
     * Set the Atheros Advanced Capabilities from station config before
     * starting 802.11 state machine.
     */
     /* TBD */

    /* this matches the FW default value */
    scn->arp_override = WME_AC_VO;
    scn->igmpmld_override = 0;
    scn->igmpmld_tid = 0;

    /* set default mgmt retry limit */
    scn->scn_mgmt_retry_limit = DEFAULT_MGMT_RETRY_LIMIT;

    /* Set the mac address */

    /* Setup Min frame size */
    ic->ic_minframesize = sizeof(struct ieee80211_frame_min);

    ic->id_mask_vap_downed = 0;

    /*
     * Setup some device specific ieee80211com methods
     */
    ic->ic_init = ol_ath_init;
    ic->ic_reset_start = ol_ath_reset_start;
    ic->ic_reset = ol_ath_reset;
    ic->ic_reset_end = ol_ath_reset_end;
    ic->ic_updateslot = ol_ath_updateslot;
    ic->ic_wme.wme_update = ol_ath_wmm_update;
    ic->ic_txq_depth = ol_ath_txq_depth;
    ic->ic_txq_depth_ac = ol_ath_txq_depth_ac;
    ic->ic_update_protmode = ol_ath_update_protmode;
    ic->ic_chwidth_change = ol_net80211_chwidth_change;
    ic->ic_nss_change = ol_net80211_nss_change;
    ic->ic_ar900b_fw_test = ol_ath_ar900b_fw_test;
    ic->ic_set_ant_switch = ol_ath_set_ant_switch_tbl;
    ic->ic_set_ctrl_table = ol_ath_set_ctl_table;
    ic->ic_start_csa = ieee80211_start_csa;
    ic->ic_set_beacon_interval = ol_set_beacon_interval;
    ic->ic_set_sta_fixed_rate = ol_net80211_set_sta_fixed_rate;
    ic->ic_support_phy_mode = ol_ath_support_phy_mode;
    ic->ic_get_bw_nss_mapping = ol_ath_get_bw_nss_mapping;

    /* dummy scan start/end commands */
    ic->ic_scan_start = ol_ath_scan_start;
    ic->ic_scan_end = ol_ath_scan_end;
#if ATH_SUPPORT_VOW_DCS
	/* host side umac compiles with this flag, so we have no
	   option than writing this with flag, otherwise the other
	   drivers in oher OSes would fail*/
    ic->ic_disable_dcsim = ol_ath_disable_dcsim;
    ic->ic_enable_dcsim = ol_ath_enable_dcsim;
#endif
    ic->ic_disable_dcscw = ol_ath_disable_dcscw;
#if ATH_SUPPORT_FIPS
    ic->ic_fips_test = ol_ath_fips_test;
#endif
    ic->ic_whal_mcs_to_kbps = whal_mcs_to_kbps;
    /* Attach the offload specific print scan function */
    ic->ic_print_scan_config = ol_print_scan_config;
    /* Attach resmgr module */
    ol_ath_resmgr_attach(ic);

    /* attach scan module */
#if UMAC_SCAN_OFFLOAD
    ol_ath_scan_attach(ic);
#else
    ieee80211_scan_class_attach(ic);
#endif

    ol_ath_power_attach(ic);

    /*
     * Attach ieee80211com object to net80211 protocal stack.
     */
    error = ieee80211_ifattach(ic, ieee80211_conf_parm);
    if (error) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ieee80211_ifattach failed error : %d\n", error);
    	return error;
    }

     /*
     * Complete device specific ieee80211com methods init
     */
    ic->ic_set_channel = ol_ath_set_channel;
    ic->ic_enable_radar = ol_ath_net80211_enable_radar;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
    ic->ic_enable_sta_radar =  ol_ath_net80211_enable_sta_radar;
#endif

    ic->ic_pwrsave_set_state = ol_ath_pwrsave_set_state;
    ic->ic_mhz2ieee = ol_ath_mhz2ieee;
    ic->ic_get_noisefloor = ol_ath_get_noisefloor;
    ic->ic_get_chainnoisefloor = ol_ath_get_chainnoisefloor;
    ic->ic_set_txPowerLimit = ol_ath_setTxPowerLimit;
    ic->ic_get_common_power = ol_ath_get_common_power;
    ic->ic_get_TSF32        = ol_ath_getTSF32;
    ic->ic_rmgetcounters = ol_ath_getrmcounters;
    ic->ic_get_wpsPushButton = ol_ath_wpsPushButton;
    ic->ic_clear_phystats = ol_ath_clear_phystats;
    ic->ic_set_macaddr = ol_ath_set_macaddr;
    ic->ic_log_text = ol_ath_log_text;
    ic->ic_log_text_bh = ol_ath_log_text_bh;
    ic->ic_set_chain_mask = ol_ath_set_chain_mask;
    ic->ic_get_mfpsupport = ol_ath_getmfpsupport;
    ic->ic_set_hwmfpQos   = ol_ath_setmfpQos;
    ic->ic_get_tx_hw_retries  = ol_ath_get_tx_hw_retries;
    ic->ic_get_tx_hw_success  = ol_ath_get_tx_hw_success;
    ic->ic_rate_node_update = ol_ath_rate_node_update;
#if ATH_SUPPORT_IQUE
    ic->ic_set_acparams = ol_ath_set_acparams;
    ic->ic_set_rtparams = ol_ath_set_rtparams;
    ic->ic_get_iqueconfig = ol_ath_get_iqueconfig;
    ic->ic_set_hbrparams = ol_ath_set_hbrparams;
#endif
    ic->ic_set_config = ol_ath_set_config;
    ic->ic_set_safemode = ol_ath_set_safemode;
    ic->ic_set_dropunenc = ol_ath_set_drop_unenc;
    ic->ic_set_privacy_filters = ol_ath_set_privacy_filters;

#ifdef ATH_SUPPORT_TxBF // For TxBF RC

#if IEEE80211_DEBUG_REFCNT
    ic->ic_ieee80211_find_node_debug = ieee80211_find_node_debug;
#else
    ic->ic_ieee80211_find_node = ieee80211_find_node;
#endif //IEEE80211_DEBUG_REFCNT
    ic->ic_v_cv_send = ol_ath_net80211_v_cv_send;
    ic->ic_txbf_alloc_key = ol_ath_net80211_txbf_alloc_key;
    ic->ic_txbf_set_key = ol_ath_net80211_txbf_set_key;
    ic->ic_init_sw_cv_timeout = ol_ath_net80211_init_sw_cv_timeout;
    ic->ic_set_txbf_caps = ol_ath_set_txbfcapability;
#ifdef TXBF_DEBUG
	ic->ic_txbf_check_cvcache = ol_ath_net80211_txbf_check_cvcache;
#endif
    ic->ic_txbf_stats_rpt_inc = ol_ath_net80211_txbf_stats_rpt_inc;
    ic->ic_txbf_set_rpt_received = ol_ath_net80211_txbf_set_rpt_received;
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	ic->ic_hifitbl_update_target = ol_ieee80211_me_hifitbl_update_target;
#endif
    ic->ic_get_cur_chan_nf = ol_ath_net80211_get_cur_chan_noisefloor;
    ic->ic_set_rxfilter = ol_ath_set_rxfilter;
    ic->ic_set_ctl_table = ol_ath_set_ctl_table;
    ic->ic_set_mimogain_table = ol_ath_set_mimogain_table;
    ic->ic_ratepwr_table_ops = ol_ath_ratepwr_table_ops;
    ic->ic_set_ratepwr_chainmsk = ol_ath_set_ratepwr_chainmsk;
    ic->ic_set_node_tpc = ol_ath_set_node_tpc;
    ic->ic_set_mgmt_retry_limit = ol_ath_set_mgmt_retry_limit;
    ic->ic_get_mgmt_retry_limit = ol_ath_get_mgmt_retry_limit;
#if ATH_BAND_STEERING
    ic->ic_bs_enable = ol_ath_bs_enable;
    ic->ic_bs_set_overload = ol_ath_bs_set_overload;
    ic->ic_bs_set_params = ol_ath_bs_set_params;
#endif
#if ATH_SUPPORT_LOWI
    ic->ic_lowi_frame_send = ol_ath_lowi_data_req_to_fw;
#endif
#if QCA_AIRTIME_FAIRNESS
    ic->ic_node_buf_held = ol_ath_net80211_node_buf_held;
    ic->atf_txbuf_max = -1;
    ic->atf_txbuf_min = -1;
    ic->atf_txbuf_share = 0;
#endif
    ic->ic_tr69_request_process = ol_ath_net80211_tr69_process_request;
    /*
     * In Offload case 'inactivity' is handled in the firmware.
     * So override the default function with a different one to handle other timeouts.
     */
    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_inact_timer), ol_ath_timeout,
            (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);

    ic->ic_nl_handle = NULL;
#if QCA_LTEU_SUPPORT
    ol_ath_nl_attach(ic);
#endif

    /*
     * pktlog scn initialization
     */
#ifndef REMOVE_PKT_LOG
    if(enable_pktlog_support)
        ol_pktlog_attach(scn);
#endif

#if QCA_AIRTIME_FAIRNESS
    spin_lock_init(&ic->atf_lock);
    ic->ic_set_atf = ol_ath_set_atf;
    ic->ic_send_atf_peer_request = ol_ath_send_atf_peer_request;
    ic->ic_set_atf_grouping = ol_ath_set_atf_grouping;
    ic->ic_set_bwf = ol_ath_set_bwf;
#endif

#ifdef QCA_PARTNER_PLATFORM
    ic->partner_com_params.ipc_ol_txrx_ast_find_hash_find = ol_txrx_ast_find_hash_find;
    ic->partner_com_params.ipc_ol_txrx_peer_find_by_id = ol_txrx_peer_find_by_id;
    ic->partner_com_params.ipc_ol_ath_getvap = ol_ath_getvap;
#endif

#if ATH_SUPPORT_IQUE
    ol_if_me_setup(ic);
#endif

#if ATH_SUPPORT_SPECTRAL
    if (ol_if_spectral_setup(ic) == 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "SPECTRAL : Not supported\n");
    }
#endif

#if ATH_SUPPORT_GREEN_AP
    if (ol_if_green_ap_attach(ic) == 0) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "GREEN-AP : Not supported\n");
    }
#endif  /* ATH_SUPPORT_GREEN_AP */

    ol_if_eeprom_attach(ic);

    ol_ath_wow_attach(ic);
    ol_ath_stats_attach(ic);
    ol_ath_smart_ant_attach(ic);

#if ATH_OL_FAST_CHANNEL_RESET_WAR
    ol_ath_fast_chan_change(scn);
#endif

    ic->ic_no_vlan = 0;
    ic->ic_atf_logging = 0;

    return EOK;
}

int
ol_asf_adf_attach(struct ol_ath_softc_net80211 *scn)
{
    osdev_t osdev = scn->sc_osdev;

    asf_adf_attach();

    /*
     * Also allocate our own dedicated asf_amem instance.
     * For now, this dedicated amem instance will be used by the
     * HAL's ath_hal_malloc.
     * Later this dedicated amem instance will be used throughout
     * the driver, rather than using the shared asf_amem instance.
     *
     * The platform-specific code that calls this ath_attach function
     * may have already set up an amem instance, if it had to do
     * memory allocation before calling ath_attach.  So, check if
     * scn->amem.handle is initialized already - if not, set it up here.
     */
    if (!scn->amem.handle) {
        qdf_spinlock_create(&scn->amem.lock);
        scn->amem.handle = asf_amem_create(
            NULL, /* name */
            0,  /* no limit on allocations */
            (asf_amem_alloc_fp) qdf_mem_alloc_outline,
            (asf_amem_free_fp) qdf_mem_free_outline,
            (void *) osdev,
            (asf_amem_lock_fp) qdf_spin_lock_bh_outline,
            (asf_amem_unlock_fp) qdf_spin_unlock_bh_outline,
            (void *) &scn->amem.lock,
            NULL /* use qdf_mem_malloc + osdev to alloc this amem object */);
        if (!scn->amem.handle) {
            qdf_spinlock_destroy(&scn->amem.lock);
            return -ENOMEM;
        }
    }

    return EOK;
}

int
ol_asf_adf_detach(struct ol_ath_softc_net80211 *scn)
{
    if(scn->amem.handle) {
        qdf_spinlock_destroy(&scn->amem.lock);
        asf_amem_destroy(scn->amem.handle, NULL);
        scn->amem.handle = NULL;
    }
    return EOK;
}

static OS_TIMER_FUNC(ieee80211_mu_cap_mode_switch)
{
    struct     ieee80211com *ic;
    struct     ieee80211_node_table *nt;
    struct     ieee80211vap *vap = NULL;
    DEDICATED_CLIENT_MAC *dedicated, *temp;
    u_int8_t   i = 0;
    u_int16_t  associd;
    u_int16_t  total_mu_clients;

    MU_CAP_CLIENT_TYPE mu_type;
    ATH_LIST_HEAD(,DEDICATED_CLIENT_MAC)deauth_list;
    MU_CAP_WAR *war;
    LIST_INIT(&deauth_list);

    OS_GET_TIMER_ARG(vap, struct ieee80211vap *);

    /*mu_cap timer enrty*/
    ic = vap->iv_ic;
    nt = &ic->ic_sta;
    war = &vap->iv_mu_cap_war;
    qdf_spin_lock_bh(&war->iv_mu_cap_lock);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,"IN Dedicated client TIMER\n");
    if (!war->mu_cap_war) {
        /*
         * Kicking out the dedicated SU Clients is
         * the only valid timer action
         * when the WAR is disabled.
         * You would never want to kick out
         * Dedicated-MU enabled client when WAR is
         * disabled!!
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "In timer while MUCAP-WAR is disabled\n");
        war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_SU_CLIENTS;
    }


    total_mu_clients = war->mu_cap_client_num[MU_CAP_CLIENT_NORMAL] +
        war->mu_cap_client_num[MU_CAP_DEDICATED_MU_CLIENT] +
        war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT];

    if ((war->mu_timer_cmd == MU_CAP_TIMER_CMD_KICKOUT_DEDICATED) &&
            ((total_mu_clients != 1) ||
             (war->mu_cap_client_num[MU_CAP_DEDICATED_MU_CLIENT] != 1))) {
        /*
         * Even thought the timer was started with the
         * purpose of kicking out MU-1X1 clients,
         * now, the conditions are not correct for kicking
         * out this MU-1X1 client,
         * possibly because other MU-Capable client(s) have joined
         */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                "Kick-out to SU-Capable 2x2 not possible now\n");
        goto end_of_timer;
    }

    switch(war->mu_timer_cmd)
    {
        case MU_CAP_TIMER_CMD_KICKOUT_DEDICATED:
            {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "KICKOUT-DEDICATED-MU-CLIENT\n");
                mu_type = MU_CAP_DEDICATED_MU_CLIENT;
                break;
            }
        case MU_CAP_TIMER_CMD_KICKOUT_SU_CLIENTS:
            {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "KICKOUT-ALL-DEDICATED-SU-CLIENTS\n");
                mu_type = MU_CAP_DEDICATED_SU_CLIENT;
                break;
            }
        default:
            {
                goto end_of_timer;
            }
    }


    /*
     * Copy the clients which meet the kick-out conditions
     * to a local table, then deauth them
     * outside of the iv_mu_cap_lock
     * This way the function ieee80211_mu_cap_client_leave can be
     * put inside iv_mu_cap_lock again
     */
    for(i=0;i<total_mu_clients;i++)
    {
        if (war->mu_cap_client_flag[i] == mu_type)
        {
            dedicated =
            OS_MALLOC(ic->ic_osdev, sizeof(struct DEDICATED_CLIENT_MAC), 0);
            if (dedicated == NULL) {
                ieee80211_note(vap, IEEE80211_MSG_ANY, "ERROR!! Memory "
                    "allocation failed in %s\n", __func__);
                continue;
            }
            OS_MEMCPY(dedicated->macaddr, war->mu_cap_client_addr[i],
                      IEEE80211_ADDR_LEN);
            LIST_INSERT_HEAD(&deauth_list, dedicated, list);
        }

    }

end_of_timer:
    war->iv_mu_timer_state = MU_TIMER_STOP;
    qdf_spin_unlock_bh(&war->iv_mu_cap_lock);

    /*
     * We now release the lock and call the
     * deauth function. The lock will be acquired later on
     * when the deauth function results in ieee80211_mu_cap_client_leave
     */
    /*De-assoc each dedicated clients*/
    LIST_FOREACH_SAFE(dedicated, &deauth_list, list, temp) {
        struct ieee80211_node *ni = ieee80211_find_node(nt, dedicated->macaddr);
        LIST_REMOVE(dedicated, list);
        OS_FREE(dedicated);
        if (ni == NULL)
        {
            ieee80211_note(vap, IEEE80211_MSG_ANY,
                    "NI IS NULL AFTER MU-CAP-WAR TIMER LOCK! %s\n",
                    ether_sprintf(dedicated->macaddr));
            continue;
        }
        if (ni->ni_associd != 0 )
        {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                    "MUCAPWAR TIMER: Kicking out %s\n",
                            ether_sprintf(ni->ni_macaddr));
            associd = ni->ni_associd;
            wlan_mlme_deauth_request(ni->ni_vap,ni->ni_macaddr,
                    IEEE80211_REASON_UNSPECIFIED);
            IEEE80211_DELIVER_EVENT_MLME_DEAUTH_INDICATION(ni->ni_vap,
                    ni->ni_macaddr, associd, IEEE80211_REASON_UNSPECIFIED);
        }
        ieee80211_free_node(ni);
    }
}

void ieee80211_mucap_vattach(struct ieee80211vap *vap) {
   struct ieee80211com *ic = vap->iv_ic;
   int cnt;
   MU_CAP_WAR *war = &vap->iv_mu_cap_war;
   osdev_t os_handle = ic->ic_osdev;
   war->iv_mu_timer_state = MU_TIMER_STOP;

   OS_INIT_TIMER(os_handle, &war->iv_mu_cap_timer,
           ieee80211_mu_cap_mode_switch, vap, QDF_TIMER_TYPE_WAKE_APPS);

   qdf_spinlock_create(&war->iv_mu_cap_lock);
   war->mu_cap_timer_period = MU_TIMER_PERIOD;

   for(cnt=0;cnt<ARRAY_SIZE(war->dedicated_client_list);cnt++) {
       LIST_INIT(&war->dedicated_client_list[cnt]);
   }
   war->dedicated_client_number = 0;

   /* Disable MU-CAP-WAR by default */
   war->modify_probe_resp_for_dedicated =
   war->mu_cap_war = 0;
}

void ieee80211_mucap_vdetach(struct ieee80211vap *vap) {

   struct DEDICATED_CLIENT_MAC *dedicated_mac=NULL, *temp=NULL;
   int cnt;
   MU_CAP_WAR *war = &vap->iv_mu_cap_war;
   qdf_spin_lock_bh(&war->iv_mu_cap_lock);
   if (war->iv_mu_timer_state == MU_TIMER_PENDING)
      war->iv_mu_timer_state = MU_TIMER_STOP;
   OS_FREE_TIMER(&war->iv_mu_cap_timer);
   qdf_spin_unlock_bh(&war->iv_mu_cap_lock);
   for(cnt=0;cnt<ARRAY_SIZE(war->dedicated_client_list);cnt++) {
       LIST_FOREACH_SAFE(dedicated_mac, &war->dedicated_client_list[cnt],
                         list, temp) {

           war->dedicated_client_number--;
           LIST_REMOVE(dedicated_mac,list);
           OS_FREE(dedicated_mac);
       }
   }
   qdf_spinlock_destroy(&war->iv_mu_cap_lock);
}


/* To check if chip is a derivative of AR900B */
void ol_scn_is_target_ar900b(struct ol_ath_softc_net80211 *scn)
{
    switch(scn->target_type)
    {
        case TARGET_TYPE_AR900B:
        case TARGET_TYPE_QCA9984:
        case TARGET_TYPE_IPQ4019:
        case TARGET_TYPE_QCA9888:
            scn->is_ar900b = true;
            break;
        default:
            scn->is_ar900b = false;
    }
}

#if ATH_SUPPORT_CODESWAP
static void ol_swap_seg_free(struct ol_ath_softc_net80211 *scn, struct swap_seg_info *seg_info, u_int64_t *cpuaddr, int type)
{
#if WIFI_MEM_MANAGER_SUPPORT
	struct ieee80211com *ic = &scn->sc_ic;
#endif
    if(cpuaddr) {
#if WIFI_MEM_MANAGER_SUPPORT
        wifi_cmem_free(ic->interface_id, (CM_CODESWAP + type), seg_info->seg_cpuaddr[0]);
#else
        dma_free_coherent(scn->sc_osdev->device, seg_info->seg_size, (void *)(unsigned long)seg_info->seg_cpuaddr[0] , (dma_addr_t)seg_info->seg_busaddr[0]);
#endif
        devm_kfree(scn->sc_osdev->device, seg_info);
    }
}
void
ol_codeswap_detach (struct ol_ath_softc_net80211 *scn) {
    ol_swap_seg_free(scn, scn->target_otp_codeswap_seginfo, scn->target_otp_codeswap_cpuaddr, ATH_TARGET_OTP_CODE_SWAP);
    ol_swap_seg_free(scn, scn->target_otp_dataswap_seginfo, scn->target_otp_dataswap_cpuaddr, ATH_TARGET_OTP_DATA_SWAP);
    ol_swap_seg_free(scn, scn->target_bin_codeswap_seginfo, scn->target_bin_codeswap_cpuaddr, ATH_TARGET_BIN_CODE_SWAP);
    ol_swap_seg_free(scn, scn->target_bin_dataswap_seginfo, scn->target_bin_dataswap_cpuaddr, ATH_TARGET_BIN_DATA_SWAP);
    ol_swap_seg_free(scn, scn->target_bin_utf_codeswap_seginfo, scn->target_bin_utf_codeswap_cpuaddr,ATH_TARGET_BIN_UTF_CODE_SWAP);
    ol_swap_seg_free(scn, scn->target_bin_utf_dataswap_seginfo, scn->target_bin_utf_dataswap_cpuaddr,ATH_TARGET_BIN_UTF_DATA_SWAP);
}
#endif

int
ol_mempools_attach(struct ol_ath_softc_net80211 *scn)
{
    if(qdf_mempool_init(scn->qdf_dev, &scn->mempool_ol_ath_vap,
         scn->max_vaps, sizeof(struct ol_ath_vap_net80211), 0)) {
         scn->mempool_ol_ath_vap = NULL;
         QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: ol_ath_vap memory pool init failed\n", __func__);
         goto fail1;
     }

    if(qdf_mempool_init(scn->qdf_dev, &scn->mempool_ol_ath_node,
        (CFG_MAX_TMPNODES + scn->max_vaps + scn->max_clients), sizeof(struct ol_ath_node_net80211), 0)) {
        scn->mempool_ol_ath_node = NULL;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: ol_ath_node memory pool init failed\n", __func__);
        goto fail2;
    }
    return 0;

fail2:
    qdf_mempool_destroy(scn->qdf_dev, scn->mempool_ol_ath_vap);
fail1:
    return -ENOMEM;
}

void
ol_mempools_detach(struct ol_ath_softc_net80211 *scn)
{
    qdf_mempool_destroy(scn->qdf_dev, scn->mempool_ol_ath_peer);
    qdf_mempool_destroy(scn->qdf_dev, scn->mempool_ol_ath_node);
    qdf_mempool_destroy(scn->qdf_dev, scn->mempool_ol_ath_vap);
}

/* Get default value of 80+80 EMI WAR enabled status based on chipset ID */
static u_int8_t
ol_ath_get_emiwar_80p80_defval(struct ol_ath_softc_net80211 *scn)
{
    u_int8_t defval=0;

    if (!IS_EMIWAR_80P80_APPLICABLE(scn)) {
        return 0;
    }

    switch(scn->target_type)
    {
        case TARGET_TYPE_QCA9984:
            defval = EMIWAR_80P80_DEFVAL_QCA9984;
            break;
        case TARGET_TYPE_QCA9888:
            defval = EMIWAR_80P80_DEFVAL_QCA9888;
            break;
        default:
            defval = 0;
            break;
    }

    return defval;
}
int ol_ath_handle_wmi_message(void *sc, void *ev, uint8_t rx_ctx)
{
void __wmi_control_rx(struct wmi_unified *wmi_handle, wmi_buf_t evt_buf);
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *) sc;

    __wmi_control_rx(scn->wmi_handle, ev);
    return 0;
}

static struct wmi_rx_ops rx_ops = {
    ol_ath_handle_wmi_message
};

int ol_target_init(struct ol_ath_softc_net80211 *scn, bool first)
{
    int status = 0;
#ifdef AH_CAL_IN_FLASH_PCI
    u_int32_t cal_location;
#endif
    struct hif_target_info *tgt_info;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    /* Create workqueue */
    scn->alloc_task_wqueue = ATH_CREATE_WQUEUE(WQNAME(alloc_task_wqueue));
    if(!scn->alloc_task_wqueue) {
        qdf_print("%s: Allocation of workqueue failed\n", __func__);
        status = -1;
        return status;
    }
#endif

#ifdef AH_CAL_IN_FLASH_PCI
#define HOST_CALDATA_SIZE (16 * 1024)
    scn->cal_in_flash = 1;
    cal_location = CalAddr[scn->cal_idx-1];
#ifndef ATH_CAL_NAND_FLASH
    scn->cal_mem = A_IOREMAP(cal_location, HOST_CALDATA_SIZE);
    if (!scn->cal_mem) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: A_IOREMAP failed\n", __func__);
        return -1;
    }
    else
    {
        qdf_print("\n scn->cal_mem %p AH_CAL_LOCATIONS_PCI %x HOST_CALDATA_SIZE %x\n",
                scn->cal_mem, cal_location, HOST_CALDATA_SIZE);
    }
#endif
#endif
#ifdef AH_CAL_IN_FILE_HOST
    scn->cal_in_file = 1;
#endif

#if ATH_DEBUG
    scn->rtsctsenable = 0;
#endif


    /*
     * 1. Initialize BMI
     */
    BMIInit(scn);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() BMI inited.\n", __func__);

    if (!scn->is_sim) {
        unsigned int bmi_user_agent;
        struct bmi_target_info targ_info;

        /*
         * 2. Get target information
         */
        OS_MEMZERO(&targ_info, sizeof(targ_info));
        if (BMIGetTargetInfo(scn->hif_hdl, &targ_info, scn) != A_OK) {
            status = -1;
            goto attach_failed;
        }
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() BMI Get Target Info.\n", __func__);
        scn->target_type = targ_info.target_type;
        ol_scn_is_target_ar900b(scn);
        scn->target_version = targ_info.target_ver;
        tgt_info = hif_get_target_info_handle(scn->hif_hdl);
        tgt_info->target_version = scn->target_version;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Chip id: 0x%x, chip version: 0x%x\n", scn->target_type, scn->target_version);
        ol_ath_host_config_update(scn);
        bmi_user_agent = ol_ath_bmi_user_agent_init(scn);
        if (bmi_user_agent) {
            /* User agent handles BMI phase */
            int rv;

            rv = ol_ath_wait_for_bmi_user_agent(scn);
            if (rv) {
                status = -1;
                goto attach_failed;
            }
        } else {
            /* Driver handles BMI phase */

            /*
             * 3. Configure target
             */
            if (ol_ath_configure_target(scn) != EOK) {
                status = -1;
                goto attach_failed;
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() configure Target .\n", __func__);

            /*
             * 4. Download firmware image and data files
             */
            if (ol_ath_download_firmware(scn) != EOK)
            {
                status = -EIO;
                goto attach_failed;
            }
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() Download FW done. \n", __func__);
        }
    }

    return 0;
attach_failed:
    return status;
}

int htc_wmi_init(struct ol_ath_softc_net80211 *scn)
{
    HTC_INIT_INFO  htcInfo;

    /*
     * 5. Create HTC
     */
    OS_MEMZERO(&htcInfo,sizeof(htcInfo));
    htcInfo.pContext = scn;
    htcInfo.TargetFailure = ol_target_failure;
    htcInfo.TargetSendSuspendComplete = ol_target_send_suspend_complete;
    htc_global_credit_flow_disable();

    if ((scn->htc_handle = htc_create(scn->hif_hdl, &htcInfo, scn->qdf_dev,0)) == NULL)
    {
        return -EIO;
    }
    qdf_print(KERN_INFO"%s() HT Create . %p\n", __func__, scn->htc_handle);

    /*
     * 6. Complete BMI phase
     */

    if (BMIDone(scn->hif_hdl, scn) != A_OK)
    {
        return -EIO;
    }


    if (!bypasswmi) {
        /*
         * 7. Initialize WMI
         */

        /* initialize default target config */
        if (scn->is_ar900b) {
            /* Beeliner supports HW IP header alignment,
             * so native WIFI support is disabled and host receives 802.3 packets
             * with IP header aligned to 4-byte boundary.
             */
            scn->host_80211_enable = 0;
            scn->nss_nwifi_offload = 0;
        }

        else if (scn->target_type == TARGET_TYPE_AR9888) {
            /* Peregrine does not support HW IP header alignment,
             * so native WIFI support should be enabled as IP header is always aligned
             * to 4-byte boundary in this mode.
             */
#if PERE_IP_HDR_ALIGNMENT_WAR
            scn->host_80211_enable = 1;
#else
            scn->host_80211_enable = 0;
#endif

#if QCA_NSS_NWIFI_MODE
            scn->nss_nwifi_offload = 1;
#else
            scn->nss_nwifi_offload = 0;
#endif
        }
    }
    qdf_print(KERN_INFO"%s %d host_enable %d nss_nwifi_offload %d\n", __func__, __LINE__,
            scn->host_80211_enable, scn->nss_nwifi_offload);

    ol_ath_set_default_tgt_config(scn);

    return 0;
}
int ol_target_init_complete(struct ol_ath_softc_net80211 *scn)
{
    int status = 0;

    if (htc_wmi_init(scn))
	    goto attach_failed;

#if WLAN_FEATURE_FASTPATH
    hif_enable_fastpath(scn->hif_hdl);
#endif

    if (htc_wait_target(scn->htc_handle) != A_OK) {
        status = -EIO;
	    goto attach_failed;
    }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (scn->nss_wifi_ol_mode) {
        osif_nss_ol_post_recv_buffer(scn);
    }
#endif

    if (!bypasswmi) {
        dbglog_init(scn);
        scn->dbg_log_init = 1;
        /* FIXME: casting sc_osdev to qdf_device is not ok for all OS
           (not an issue for linux as linux ignores the handle) */
        /*
         * ol_txrx_pdev_attach needs to be called after calling
         * htc_wait_target but before calling htc_start, so HTT can
         * do its HTC service connection.
         */
        scn->pdev_txrx_handle = ol_txrx_pdev_attach((ol_pdev_handle)scn,
                                                    scn->htc_handle,
                                                    scn->qdf_dev);
        if (scn->pdev_txrx_handle == NULL) {
            qdf_print("%s: pdev attach failed\n",__func__);
            goto attach_failed;
        }
    }

    if ((status = ol_ath_connect_htc(scn)) != A_OK)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: connect_htc failed\n",__func__);
        goto attach_failed;
    }

    if (!bypasswmi) {
        /*
         * Invoke the host datapath initializations that involve messages
         * to the target.
         * (This can't be done until after the htc_start call, which is in
         * ol_ath_connect_htc.)
         */
        if (scn->target_version != AR6004_VERSION_REV1_3) {
            if (ol_txrx_pdev_attach_target(scn->pdev_txrx_handle) != A_OK) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: txrx pdev attach failed\n",__func__);
                goto attach_failed;
            }
        }
    }

    return 0;
attach_failed:
    return -EIO;
}

int
ol_ath_attach(u_int16_t devid, struct ol_ath_softc_net80211 *scn,
              IEEE80211_REG_PARAMETERS *ieee80211_conf_parm,
              ol_ath_update_fw_config_cb cfg_cb)
{
    struct ieee80211com     *ic = &scn->sc_ic;
    int status = 0, idx = 0;
    osdev_t osdev = scn->sc_osdev;
#if DBDC_REPEATER_SUPPORT
    int i,j,k;
    struct ieee80211com     *tmp_ic;
#endif

    ic->interface_id = ath_get_radio_index(scn->sc_osdev->netdev);
    qdf_print("%s interface_id %d\n",__func__,ic->interface_id);

    ic->ic_auth_tx_xretry = 0;
#if ATH_SUPPORT_DSCP_OVERRIDE
	/* Initializing tid-map parameters to default vaules. */
	OS_MEMCPY(ic->ic_dscp_tid_map,dscp_tid_map, sizeof(A_UINT32) * WMI_HOST_DSCP_MAP_MAX);
	ic->ic_override_dscp = 0x00;
	ic->ic_dscp_hmmc_tid = 0x00;
	ic->ic_override_hmmc_dscp = 0x00;
#endif
    ic->ic_consider_obss_long_slot = CONSIDER_OBSS_LONG_SLOT_DEFAULT;

    qdf_spinlock_create(&scn->scn_lock);

#if ATH_SUPPORT_WRAP
    qdf_spinlock_create(&scn->sc_mpsta_vap_lock);
#endif

    /* init IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_init(ic);

    scn->cfg_cb = cfg_cb;

    /* detect low memory system */
    if (!low_mem_system) {
        if ((qdf_get_totalramsize() < LOW_MEM_SYSTEM_RAM) &&
                (scn->target_type == TARGET_TYPE_IPQ4019)) {
            //  low_mem_system is true
            low_mem_system = 1;
        }
    }

    if (ol_target_init(scn, true)) {
        status = -1;
        goto attach_failed;
    }

#if QCA_WIFI_3_0
    if ((scn->wmi_handle = wmi_unified_attach(scn, osdev, WMI_TLV_TARGET,
                       0, &rx_ops)) == NULL)
#else
    if ((scn->wmi_handle = wmi_unified_attach(scn, osdev, WMI_NON_TLV_TARGET,
                       0, &rx_ops)) == NULL)
#endif
    {
        qdf_print("%s() Failed to initialize WMI.\n", __func__);
        status = -1;
        goto attach_failed;
    }
    qdf_print(KERN_INFO"%s() WMI attached. wmi_handle %p \n", __func__, scn->wmi_handle);

#if WMI_RECORDING
    wmi_proc_create(scn->wmi_handle, scn->wmi_proc_entry, ath_get_radio_index(scn->sc_osdev->netdev));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_service_ready_event_id,
                                        ol_ath_service_ready_event, WMI_RX_WORK_CTX);
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_service_ready_ext_event_id,
                                        ol_ath_service_ready_ex_event, WMI_RX_WORK_CTX);
#else
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_service_ready_event_id,
                                        ol_ath_service_ready_event, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_service_ready_ext_event_id,
                                        ol_ath_service_ready_ex_event, WMI_RX_UMAC_CTX);
#endif
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_ready_event_id,
                                        ol_ath_ready_event, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_debug_print_event_id,
                                            ol_ath_debug_print_event_handler, WMI_RX_UMAC_CTX);
#if ATH_SUPPORT_FIPS
	/* Initialize FIPS WMI Event */
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_pdev_fips_event_id,
                                           ol_ath_fips_event_handler, WMI_RX_UMAC_CTX);
#endif

    osif_register_dev_ops_xmit(osif_ol_ll_vap_hardstart, OSIF_NETDEV_TYPE_OL);

    if (ol_target_init_complete(scn)) {
        status = -1;
        goto attach_failed;
    }

    /*
     * 8. Connect Services to HTC
     */
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	scn->buff_thresh.ald_free_buf_lvl = scn->buff_thresh.pool_size - (( scn->buff_thresh.pool_size * 75 ) / 100);
	scn->buff_thresh.ald_buffull_wrn = 0;
#endif

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() connect HTC. \n", __func__);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"bypasswmi : %d\n",bypasswmi);
    if (!bypasswmi) {
        // Use attach_failed1 for failures beyond this
        /*
         * 9. WLAN/UMAC initialization
         */
        ic->ic_is_mode_offload = ol_ath_net80211_is_mode_offload;
        ic->ic_if_mgmt_drain = ol_if_mgmt_drain;
        ic->ic_is_macreq_enabled = ol_ath_net80211_is_macreq_enabled;
        ic->ic_get_mac_prealloc_idmask = ol_ath_net80211_get_mac_prealloc_idmask;
        ic->ic_osdev = osdev;
        ic->ic_qdf_dev = scn->qdf_dev;
        if (scn->target_version == AR6004_VERSION_REV1_3) {
        /*
           It's Hard code for HAL capability and We don't use this branch for McKinley.
           Because McKinley don't support WMI UNIFIED SERVICE READY,
        */
            scn->hal_reg_capabilities.eeprom_rd = 0;
            scn->hal_reg_capabilities.eeprom_rd_ext = 0x1f;
            scn->hal_reg_capabilities.high_2ghz_chan = 0xaac;
            scn->hal_reg_capabilities.high_5ghz_chan = 0x17d4;
            scn->hal_reg_capabilities.low_2ghz_chan = 0x908;
            scn->hal_reg_capabilities.low_5ghz_chan = 0x1338;
            scn->hal_reg_capabilities.regcap1 = 7;
            scn->hal_reg_capabilities.regcap2 = 0xbc0;
            scn->hal_reg_capabilities.wireless_modes = 0x1f9001;
            scn->phy_capability = 1;
            ol_regdmn_attach(scn);
            ol_regdmn_set_regdomain(scn->ol_regdmn_handle, scn->hal_reg_capabilities.eeprom_rd);
            ol_regdmn_set_regdomain_ext(scn->ol_regdmn_handle, scn->hal_reg_capabilities.eeprom_rd_ext);
        }

        if (wmi_service_enabled(scn->wmi_handle, wmi_service_restrt_chnl_support)) {
            ic->ic_rch_params.restrict_channel_support = 1;
            ic->ic_rch_params.low_5ghz_chan  = scn->hal_reg_capabilities.low_5ghz_chan;
            ic->ic_rch_params.high_5ghz_chan = scn->hal_reg_capabilities.high_5ghz_chan;

            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: low_5ghz: %d  high_5gh: %d \n", __func__, scn->hal_reg_capabilities.low_5ghz_chan,
                    scn->hal_reg_capabilities.high_5ghz_chan);
        } else {
            ic->ic_rch_params.restrict_channel_support = 0;
        }

        ic->ic_emiwar_80p80 = ol_ath_get_emiwar_80p80_defval(scn);

        ol_regdmn_start(scn->ol_regdmn_handle, ieee80211_conf_parm);

        /*
        To propagate the country settings to UMAC layer so that
        tools like wlanmon is able to get the information they want
        */
        ic->ic_get_currentCountry(ic, &ic->ic_country);

        ol_ath_setup_rates(ic);
        ol_ath_phyerr_attach(ic);
        ieee80211com_set_cap_ext(ic, IEEE80211_CEXT_PERF_PWR_OFLD);
        status = ol_ath_dev_attach(scn, ieee80211_conf_parm);
        if (status) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ol_ath_dev_attach failed status %d\n", status);
            goto attach_failed;
        }
#if !ATH_SUPPORT_LOWI && ATH_SUPPORT_WIFIPOS
        if (wifiposenable)
        {
            ic->ic_rtt_init_netlink = ieee80211com_init_netlink;
            ol_ath_rtt_netlink_attach(ic);
        }
        else
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:%d: netlink socket for wifipos not created\n", __func__,__LINE__);
        }
#endif
        ic->ic_find_channel = ieee80211_find_channel;
        ic->ic_ieee2mhz = ieee80211_ieee2mhz;

#if ATH_SUPPORT_DFS
        ol_if_dfs_setup(ic);
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
		ic->ic_hmmc_cnt = 3;
		ic->ic_hmmcs[0].ip = be32toh(0xeffffffa); /* 239.255.255.250 */
		ic->ic_hmmcs[0].mask = 0xffffffff;
		ic->ic_hmmcs[1].ip = be32toh(0xe00000fb); /* 224.0.0.251 */
		ic->ic_hmmcs[1].mask = 0xffffffff;
		ic->ic_hmmcs[2].ip = be32toh(0xe00000fc); /* 224.0.0.252 */
		ic->ic_hmmcs[2].mask = 0xffffffff;
		ic->ic_check_buffull_condition = ol_ath_net80211_check_buffull_condition;
#endif

        ol_ath_vap_attach(ic);

	scn->max_clients = max_clients;
	scn->max_vaps = max_vaps;

        if ((status = ol_mempools_attach(scn))) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: ol_mempools attach failed\n",__func__);
            goto attach_failed;
        };

        if ((status = ol_txrx_mempools_attach((ol_pdev_handle)scn))) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: ol_txrx_mempools attach failed\n",__func__);
            qdf_mempool_destroy(scn->qdf_dev, scn->mempool_ol_ath_node);
            qdf_mempool_destroy(scn->qdf_dev, scn->mempool_ol_ath_vap);
            goto attach_failed;
        };

        if ((status = ol_ath_node_attach(scn, ic))) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: ol_ath_node_attach failed\n",__func__);
            goto attach_failed;
        };

        ol_ath_beacon_attach(ic);
#if ATH_SUPPORT_WIFIPOS
        ol_ath_rtt_meas_report_attach(ic);
        ic->ic_xmitrtt3 = ol_ieee80211_wifipos_xmitrtt3;
#endif
#if ATH_SUPPORT_LOWI
	ol_ath_lowi_wmi_event_attach(ic);
#endif
#ifdef QVIT
        ol_ath_qvit_attach(scn);
#endif
        ol_ath_utf_attach(scn);

        ol_ath_mgmt_attach(ic);

        ol_ath_chan_info_attach(ic);
        /* attach the dcs functionality */
        ol_ath_dcs_attach(ic);
        /* As of now setting ic with all ciphers assuming
         * hardware will support, eventually to query
         * the hardware to figure out h/w crypto support.
         */
        ieee80211com_set_cap(ic, IEEE80211_C_WEP);
        ieee80211com_set_cap(ic, IEEE80211_C_AES);
        ieee80211com_set_cap(ic, IEEE80211_C_AES_CCM);
        ieee80211com_set_cap(ic, IEEE80211_C_CKIP);
        ieee80211com_set_cap(ic, IEEE80211_C_TKIP);
        ieee80211com_set_cap(ic, IEEE80211_C_TKIPMIC);
        if (wmi_service_enabled(scn->wmi_handle, wmi_service_11ac)) {
            ieee80211com_set_cap_ext(ic, IEEE80211_CEXT_11AC);
        }

        if (ieee80211_conf_parm->wmeEnabled) {
            ieee80211com_set_cap(ic, IEEE80211_C_WME);
        }

#if ATH_SUPPORT_WAPI
        ieee80211com_set_cap(ic, IEEE80211_C_WAPI);
#endif
#if UMAC_SCAN_OFFLOAD
        ol_scan_update_channel_list(ic->ic_scanner);
#endif
        wds_addr_init(scn->wmi_handle);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_wlan_profile_data_event_id,
                                                ol_ath_wlan_profile_data_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_pdev_tpc_config_event_id,
                                                ol_ath_pdev_tpc_config_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_gpio_input_event_id,
                                                ol_ath_gpio_input_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_pdev_nfcal_power_all_channels_event_id,
                                                ol_ath_nf_dbr_dbm_info_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_pdev_tpc_event_id,
                                                ol_ath_packet_power_info_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_generic_buffer_event_id,
                                                ol_ath_generic_buffer_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_mcast_list_ageout_event_id,
                                                ol_ath_mcast_list_ageout_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_peer_tx_mu_txmit_count_event_id,
                                                ol_ath_peer_mumimo_tx_count_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_peer_gid_userpos_list_event_id,
                                                ol_ath_peer_gid_userpos_list_event_handler, WMI_RX_UMAC_CTX);
#if QCA_AIRTIME_FAIRNESS
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_atf_peer_stats_event_id,
                                                ol_ath_atf_peer_stats_event_handler, WMI_RX_UMAC_CTX);

        wmi_unified_register_event_handler(scn->wmi_handle, wmi_tx_data_traffic_ctrl_event_id,
                                                ol_ath_tx_data_traffic_ctrl_event_handler, WMI_RX_UMAC_CTX);
#endif
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_pdev_check_cal_version_event_id,
                                                ol_ath_pdev_caldata_version_check_event_handler, WMI_RX_UMAC_CTX);

#if OL_ATH_SUPPORT_LED
        if (scn->target_version == AR9888_REV2_VERSION || scn->target_version == AR9887_REV1_VERSION) {
            scn->scn_led_gpio = PEREGRINE_LED_GPIO ;
        } else if (scn->target_version ==  AR900B_DEV_VERSION) {
            scn->scn_led_gpio = BEELINER_LED_GPIO ;
        } else if (scn->target_version ==  QCA9984_DEV_VERSION) {
            scn->scn_led_gpio = CASCADE_LED_GPIO ;
        } else if (scn->target_version ==  QCA9888_DEV_VERSION) {
            scn->scn_led_gpio = BESRA_LED_GPIO ;
        }

        if(scn->target_type == TARGET_TYPE_IPQ4019) {
            scn->scn_led_gpio = 0; //will get initialized later
            ipq4019_wifi_led_init(scn);
        }


#if QCA_LTEU_SUPPORT
        if (scn->lteu_support) {
            ol_gpio_config(scn, scn->scn_led_gpio, 1, WMI_HOST_GPIO_PULL_DOWN, WMI_HOST_GPIO_INTTYPE_RISING_EDGE);
        } else {
#endif
            if(scn->target_type == TARGET_TYPE_IPQ4019) {
                //ipq4019_wifi_led(scn, LED_ON);
                /* Do not enable LED for IPQ4019 during attach, as wifi LED will keep
                   glowing even if vaps are not created for that radio */
            } else {
                ol_gpio_config(scn, scn->scn_led_gpio, 0, 0, 0);
                ol_ath_gpio_output(scn, scn->scn_led_gpio, 1);
            }

            OS_INIT_TIMER(scn->sc_osdev, &(scn->scn_led_blink_timer), ol_ath_led_blink_timed_out,
                    (void *)scn, QDF_TIMER_TYPE_WAKE_APPS);
            OS_INIT_TIMER(scn->sc_osdev, &(scn->scn_led_poll_timer), ol_ath_led_poll_timed_out,
                    (void *)scn, QDF_TIMER_TYPE_WAKE_APPS);
            scn->scn_blinking = OL_BLINK_DONE;
            scn->scn_led_byte_cnt = 0;
            scn->scn_led_last_time = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
            scn->scn_led_blink_rate_table         = ol_led_blink_rate_table;
            scn->scn_led_max_blink_rate_idx = ARRAY_LENGTH(ol_led_blink_rate_table) - 1;
#if QCA_LTEU_SUPPORT
        }
#endif
#endif /* OL_ATH_SUPPORT_LED */
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s() UMAC attach . \n", __func__);
#if ATH_SUPPORT_DFS
    /* Calling ol_if_dfs_configure here results in enabling radar detection
       for station, when all the available channels are dfs channels.
       This will be called in ol_vdev_wmi_event_handler when firmware
       sends ol_vdev_start_resp_ev. */
    /*ol_if_dfs_configure(ic);*/
#endif

    if(prealloc_disabled){
        ic->ic_scan_entry_max_count = ATH_SCANENTRY_MAX;
    } else {
        ic->ic_scan_entry_max_count = ATH_MAX_SCAN_ENTRIES;
    }
    atomic_set(&(ic->ic_scan_entry_current_count),0);
    ic->ic_scan_entry_timeout = ATH_SCANENTRY_TIMEOUT;
    /* unless user prefers not to allow the frames between different vaps, let frames route through*/
    scn->scn_block_interbss = 0;
    /*
     * Enable Bursting by default for pre-ES2 release only. Tobe removed Later
     */
    {
	    int ac, duration, value, retval;
	    ac = 0, retval = 0;
	    duration = 8000;
	    value = 2000;
	    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"\n BURSTING enabled by default\n");
	    for(ac=0;ac<=3;ac++) {
		    retval = ol_ath_pdev_set_param(scn,
				    wmi_pdev_param_aggr_burst,
				    (ac&0x0f) << 24 | (0x00ffffff & duration),
                    0);
	    }
	    if( EOK == retval) {
		    scn->aggr_burst_dur[0] = duration;
	    }

	    ol_ath_pdev_set_param(scn,
			    wmi_pdev_param_set_ppdu_duration_cmdid, value, 0);
    }

#if ATH_PROXY_NOACK_WAR
    if(scn->target_type == TARGET_TYPE_AR900B) {
        /* WAR is required only for Beeliner*/
        scn->sc_proxy_noack_war = 1;
        OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_ast_reserve_timer), ol_proxy_ast_reserve_timeout,
                (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    } else {
        /* Peregrine/Swift/Cascade/Dakota/Besra - Don't need this QWRAP WAR */
        scn->sc_proxy_noack_war = 0;
    }
#endif
#if ATH_DATA_TX_INFO_EN
    /*Alloc buffer for data TX info*/
    scn->tx_status_buf = qdf_mem_malloc(sizeof(struct ieee80211_tx_status));
#endif

#if DBDC_REPEATER_SUPPORT
    /* Add ic to global list */
    GLOBAL_IC_LOCK(&ic_list);
    ic_list.global_ic[ic_list.num_global_ic++] = ic;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Set global_ic[%d] ..ptr:%p\n", __func__, ic_list.num_global_ic,&ic_list);
    ic->ic_global_list = &ic_list;
    ic_list.dbdc_process_enable = 1;
    ic_list.force_client_mcast_traffic = 0;
    ic_list.delay_stavap_connection = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_set_force_client_mcast_traffic(ic);
#endif
    ic_list.num_stavaps_up = 0;
    ic_list.is_dbdc_rootAP = 0;
    ic_list.iface_mgr_up = 0;
    ic_list.disconnect_timeout = 10;
    ic_list.reconfiguration_timeout = 60;
    ic_list.always_primary = 0;
    ic_list.num_fast_lane_ic = 0;
    ic_list.max_priority_stavap_up = NULL;
    ic_list.drop_secondary_mcast = 0;
    GLOBAL_IC_UNLOCK(&ic_list);

    spin_lock(&ic->ic_lock);
    if (ic_list.num_global_ic) {
        /* In case of DBDC repeater configuration, pass Multicast/Broadcast and
           ethernet client traffic through this radio */
        ic->ic_radio_priority = ic_list.num_global_ic;
        if (ic_list.num_global_ic == 1) {
            ic->ic_primary_radio = 1;
        }
    }
    ic->fast_lane = 0;
    ic->fast_lane_ic = NULL;
    spin_unlock(&ic->ic_lock);

    k = 0;
    /*update other_ic list on each radio*/
    for (i=0; i < MAX_RADIO_CNT; i++) {
	GLOBAL_IC_LOCK(&ic_list);
	tmp_ic = ic_list.global_ic[i];
	GLOBAL_IC_UNLOCK(&ic_list);
	if (tmp_ic && (tmp_ic != ic) && (k < MAX_RADIO_CNT-1)) {
	    spin_lock(&ic->ic_lock);
	    ic->other_ic[k++] = tmp_ic;
	    spin_unlock(&ic->ic_lock);
	    for (j=0; j < MAX_RADIO_CNT-1 ; j++) {
		if (tmp_ic->other_ic[j] == NULL) {
		    spin_lock(&tmp_ic->ic_lock);
		    tmp_ic->other_ic[j] = ic;
		    spin_unlock(&tmp_ic->ic_lock);
		    break;
		}
	    }
	}
    }

#endif
    /*Set default monitor VAP filter to enable all input*/
    ic->mon_filter_osif_mac = 0;
    ic->ic_non_doth_sta_cnt = 0;
    ol_txrx_monitor_set_filter_ucast_data(scn->pdev_txrx_handle,0);
    ol_txrx_monitor_set_filter_mcast_data(scn->pdev_txrx_handle,0);
    ol_txrx_monitor_set_filter_non_data(scn->pdev_txrx_handle,0);

    ic->ic_stop = ol_ath_target_stop;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_wifi_monitor_set_filter(ic, MON_FILTER_ALL_DISABLE);
#endif
    return EOK;

attach_failed:

#if OL_ATH_SMART_LOGGING
    if(ic->smart_logging == 1)
    {
        smart_log_deinit(scn);
    }
#endif /* OL_ATH_SMART_LOGGING */
    /* deregister IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_deregister(ic);

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " %s error status %d\n",__func__, status);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (scn->nss_wifi_ol_mode) {
        osif_nss_ol_wifi_pause(scn);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nss wifi offload paused as %s failed\n",__FUNCTION__);
    }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (scn->nss_wifi_ol_mode) {
        osif_nss_ol_wifi_reset(scn, 0);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nss wifi offload reset as %s failed\n", __FUNCTION__);
    }
#endif

    for (idx=0; idx<scn->num_mem_chunks; ++idx) {
#if WIFI_MEM_MANAGER_SUPPORT
        wifi_cmem_free(ic->interface_id, scn->mem_chunks[idx].req_id, (int)scn->mem_chunks[idx].vaddr);
#else
        qdf_mem_free_consistent(
            scn->qdf_dev,
            &(((struct pci_dev *)(scn->qdf_dev->drv_hdl))->dev),
            scn->mem_chunks[idx].len,
            scn->mem_chunks[idx].vaddr,
	    scn->mem_chunks[idx].paddr,
            qdf_get_dma_mem_context((&(scn->mem_chunks[idx])), memctx));
#endif
    }
    scn->num_mem_chunks = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    if(scn->alloc_task_wqueue != NULL) {
        ATH_FLUSH_WQUEUE(scn->alloc_task_wqueue);
        ATH_DESTROY_WQUEUE(scn->alloc_task_wqueue);
        scn->alloc_task_wqueue = NULL;
    }
#endif

    if (scn->htc_handle) {
        htc_destroy(scn->htc_handle);
        scn->htc_handle = NULL;
    }
    BMICleanup(scn);
    if (!bypasswmi) {
        if (scn->wmi_handle) {
            wmi_unified_detach(scn->wmi_handle);
#if WMI_RECORDING
            wmi_proc_remove(scn->wmi_handle, scn->wmi_proc_entry, ath_get_radio_index(scn->sc_osdev->netdev));
#endif
            scn->wmi_handle = NULL;
        }
        if (scn->pdev_txrx_handle) {
            /* Force delete txrx pdev */
            ol_txrx_pdev_detach(scn->pdev_txrx_handle, 1);
            scn->pdev_txrx_handle = NULL;
        }
        if (scn->dbg_log_init) {
            dbglog_free(scn);
            scn->dbg_log_init = 0;
        }
    }
#ifdef AH_CAL_IN_FLASH_PCI
#ifndef ATH_CAL_NAND_FLASH
    if (scn->cal_mem) {
        A_IOUNMAP(scn->cal_mem);
        scn->cal_mem = 0;
    }
#endif
    scn->cal_in_flash = 0;
#endif
#ifdef AH_CAL_IN_FILE_HOST
    scn->cal_in_file = 0;
#endif
    return status;
}

void ol_ath_target_deinit(struct ol_ath_softc_net80211 *scn, int force)
{

#if OL_ATH_SMART_LOGGING
    struct ieee80211com *ic = &(scn->sc_ic);
#endif /* OL_ATH_SMART_LOGGING */
    ol_ath_disconnect_htc(scn);

#if OL_ATH_SMART_LOGGING
    if(ic->smart_logging == 1)
    {
        smart_log_deinit(scn);
    }
#endif /* OL_ATH_SMART_LOGGING */

    if (!bypasswmi) {
        /*
         * The call to ol_txrx_pdev_detach has to happen after the call to
         * ol_ath_disconnect_htc, so that if there are any outstanding
         * tx packets inside HTC, the cleanup callbacks into HTT and txrx
         * will still be valid.
         */
        if (scn->pdev_txrx_handle) {
            ol_txrx_pdev_detach(scn->pdev_txrx_handle, force);
            scn->pdev_txrx_handle = NULL;
        }
        dbglog_free(scn);
    }
}

void ol_ath_target_deinit_complete(struct ol_ath_softc_net80211 *scn)
{
    if (scn->htc_handle) {
        htc_destroy(scn->htc_handle);
        scn->htc_handle = NULL;
    }

    /* Cleanup BMI */
    BMICleanup(scn);

    if (scn->hif_hdl != NULL) {
        ol_hif_close(scn->hif_hdl);
        scn->hif_hdl = NULL;
    }
}

int
ol_ath_detach(struct ol_ath_softc_net80211 *scn, int force)
{
    struct ieee80211com     *ic;
    int status = 0,idx;
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com     *tmp_ic;
    int i = 0,j;
#endif
    ic = &scn->sc_ic;

#if ATH_DATA_TX_INFO_EN
    /*Free buffer for data TX info*/
    qdf_mem_free(scn->tx_status_buf);
    scn->tx_status_buf = NULL;
#endif

#if OL_ATH_SUPPORT_LED
    if (
#if QCA_LTEU_SUPPORT
        !scn->lteu_support &&
#endif
        !bypasswmi) {
            scn->scn_led_blink_rate_table = NULL;
            qdf_timer_sync_cancel(&scn->scn_led_blink_timer);
            qdf_timer_sync_cancel(&scn->scn_led_poll_timer);
            if(scn->target_type == TARGET_TYPE_IPQ4019) {
                ipq4019_wifi_led_deinit(scn);
        }
    }
#endif /* OL_ATH_SUPPORT_LED */

    if (!(scn->down_complete)) {
        ol_ath_stats_detach(ic);
    }

    wds_addr_detach(scn->wmi_handle);

    ol_ath_wow_detach(ic);

    /* deregister IEEE80211_DPRINTF_IC control object */
    ieee80211_dprintf_ic_deregister(ic);

    if (!bypasswmi) {
        ieee80211_stop_running(ic);
#if ATH_SUPPORT_DFS
        ol_if_dfs_teardown(ic);
#endif

        ol_ath_phyerr_detach(ic);
        /*
         * NB: the order of these is important:
         * o call the 802.11 layer before detaching the hal to
         *   insure callbacks into the driver to delete global
         *   key cache entries can be handled
         * o reclaim the tx queue data structures after calling
         *   the 802.11 layer as we'll get called back to reclaim
         *   node state and potentially want to use them
         * o to cleanup the tx queues the hal is called, so detach
         *   it last
         * Other than that, it's straightforward...
         */
        ieee80211_ifdetach(ic);
    }
    ol_mempools_detach(scn);
#if 0 /* TBD */
    ol_ath_vap_detach(ic);
    ol_ath_node_detach(scn, ic);
    ol_ath_beacon_detach(ic);
    ol_ath_scan_detach(ic);

    ol_ath_mgmt_detach(ic);
#endif

#if QCA_LTEU_SUPPORT
    ol_ath_nl_detach(ic);
#endif

#ifndef REMOVE_PKT_LOG
    if (scn->pl_dev){
        ol_pktlog_detach(scn);
	ol_pl_freehandle(scn->pl_dev);
        scn->pl_dev = NULL;
    }
#endif

    if (!(scn->down_complete))
        ol_regdmn_detach(scn->ol_regdmn_handle);

    qdf_spinlock_destroy(&scn->amem.lock);
    asf_amem_destroy(scn->amem.handle, NULL);
    scn->amem.handle = NULL;

    if (!(scn->down_complete))
        ol_ath_target_deinit(scn, force);
#if ATH_SUPPORT_GREEN_AP
    ol_if_green_ap_detach(ic);
#endif  /* ATH_SUPPORT_GREEN_AP */

#ifdef QVIT
    ol_ath_qvit_detach(scn);
#endif

#if OL_ATH_SMART_LOGGING
    if (ic->smart_logging == 1)
    {
        smart_log_deinit(scn);
    }
#endif /* OL_ATH_SMART_LOGGING */

    if (!bypasswmi) {
        ol_ath_utf_detach(scn);
        dbglog_free(scn);
    }

    ol_ath_smart_ant_detach(ic);

    if (!(scn->down_complete)) {
	hif_disable_isr(scn->hif_hdl);
        ol_ath_target_deinit_complete(scn);
    }

    if (!bypasswmi) {
        if (scn->wmi_handle) {
            wmi_unified_detach(scn->wmi_handle);
#if WMI_RECORDING
            wmi_proc_remove(scn->wmi_handle, scn->wmi_proc_entry, ath_get_radio_index(scn->sc_osdev->netdev));
#endif
            scn->wmi_handle =NULL;
        }
    }

#if ATH_SUPPORT_SPECTRAL
    ol_if_spectral_detach(ic);
#endif  // ATH_SUPPORT_SPECTRAL

#if !ATH_SUPPORT_LOWI && ATH_SUPPORT_WIFIPOS
    ol_if_rtt_detach(ic);
#endif
#if ATH_PROXY_NOACK_WAR
    if (scn->sc_proxy_noack_war) {
        OS_FREE_TIMER(&(ic->ic_ast_reserve_timer));
    }
#endif
#if ATH_SUPPORT_CODESWAP
    ol_codeswap_detach(scn);
#endif

#ifdef AH_CAL_IN_FLASH_PCI
#ifndef ATH_CAL_NAND_FLASH
    if (scn->cal_mem) {
        A_IOUNMAP(scn->cal_mem);
        scn->cal_mem = 0;
    }
#endif
    scn->cal_in_flash = 0;
#endif

#ifdef AH_CAL_IN_FILE_HOST
    scn->cal_in_file = 0;
#endif

#if ATH_SUPPORT_WRAP
    qdf_spinlock_destroy(&scn->sc_mpsta_vap_lock);
#endif

    qdf_spinlock_destroy(&scn->scn_lock);

    if (!(scn->down_complete)) {
    for(idx=0;idx<scn->num_mem_chunks; ++idx) {
#if WIFI_MEM_MANAGER_SUPPORT
        wifi_cmem_free(ic->interface_id, scn->mem_chunks[idx].req_id, (int)scn->mem_chunks[idx].vaddr);
#else
        qdf_mem_free_consistent(
            scn->qdf_dev,
            &(((struct pci_dev *)(scn->qdf_dev->drv_hdl))->dev),
            scn->mem_chunks[idx].len,
            scn->mem_chunks[idx].vaddr,
            scn->mem_chunks[idx].paddr,
            qdf_get_dma_mem_context((&(scn->mem_chunks[idx])), memctx));
#endif
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    if(scn->alloc_task_wqueue != NULL) {
        ATH_FLUSH_WQUEUE(scn->alloc_task_wqueue);
        ATH_DESTROY_WQUEUE(scn->alloc_task_wqueue);
        scn->alloc_task_wqueue = NULL;
    }
#endif
}

#if DBDC_REPEATER_SUPPORT
    /* Remove ic from global list */
    for (i=0; i < MAX_RADIO_CNT; i++) {
        tmp_ic = ic_list.global_ic[i];
        if (tmp_ic && (ic == tmp_ic)) {
            GLOBAL_IC_LOCK(&ic_list);
            ic_list.global_ic[i] = NULL;
            ic_list.num_global_ic--;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: remove global_ic[%d]..gloabl_ic ptr:%p\n", __func__, ic_list.num_global_ic,&ic_list);
            GLOBAL_IC_UNLOCK(&ic_list);
        }
    }
    for (i=0; i < MAX_RADIO_CNT; i++) {
        GLOBAL_IC_LOCK(&ic_list);
        tmp_ic = ic_list.global_ic[i];
        GLOBAL_IC_UNLOCK(&ic_list);
        if (tmp_ic && (tmp_ic != ic)) {
            for (j=0; j < MAX_RADIO_CNT-1 ; j++) {
                if (tmp_ic->other_ic[j] == ic) {
                    spin_lock(&tmp_ic->ic_lock);
                    tmp_ic->other_ic[j] = NULL;
                    spin_unlock(&tmp_ic->ic_lock);
                    break;
                }
            }
        }
    }
#endif
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Peer Count %d \n", __func__, qdf_atomic_read(&scn->peer_count));

    /* No Target accesses of any kind after this point */
    return status;
}

void ol_reset_params(struct ol_ath_softc_net80211 *scn)
{

    /* should always be equal to define DEFAULT_LOWEST_RATE_IN_5GHZ 0x03  6 Mbps  in firmware */
    scn->ol_rts_cts_rate                    = 0x03;
#if WDI_EVENT_ENABLE
    scn->scn_user_peer_invalid_cnt          = 0;/* By default we will send one deauth in 10 msec in response to rx_peer_invalid */
#endif
    scn->dyngroup                           = 0;
    scn->dpdenable                          = 1;
    scn->scn_amsdu_mask                     = 0xffff;
    scn->scn_amsdu_mask                     = 0xffff;
    scn->txpower_scale                      = 0;
    scn->powerscale                         = 0;
    scn->scn_dcs.dcs_enable                 = 0;
    scn->scn_dcs.coch_intr_thresh           = DCS_COCH_INTR_THRESHOLD ;
    scn->scn_dcs.phy_err_threshold          = DCS_PHYERR_THRESHOLD ;
    scn->scn_dcs.user_max_cu                = DCS_USER_MAX_CU; /* tx_cu + rx_cu */
    scn->scn_dcs.dcs_debug                  = DCS_DEBUG_DISABLE;
    scn->burst_dur                          = 0;
    scn->burst_enable                       = 1;
    scn->is_ani_enable                      = true;
    scn->dtcs                               = 0; /* Dynamic Tx Chainmask Selection enabled/disabled */
    scn->vow_extstats                       = 0;
    scn->sc_arp_dbg_conf                    = 0;
    scn->scn_stats.ap_stats_tx_cal_enable   = 0;
    scn->macreq_enabled                     = 0; /* user mac request feature enable/disable */
    scn->bcn_mode                           = 0;
    scn->arp_override                       = WME_AC_VO;
    scn->igmpmld_override                   = 0;
    scn->igmpmld_tid                        = 0;
#if ATH_RX_LOOPLIMIT_TIMER
    scn->rx_looplimit_timeout               = 1;           /* 1 ms by default */
    scn->rx_looplimit_valid                 = true;          /* set to valid after initilization */
    scn->rx_looplimit                       = false;
#endif
    scn->sc_prealloc_idmask                 = 0;
    scn->recovery_enable                    = 0;
    scn->sc_is_blockdfs_set                 = false;
    scn->scn_qboost_enable                  = 0;
    scn->scn_sifs_frmtype                   = 0;
    scn->scn_sifs_uapsd                     = 0;
    scn->scn_block_interbss                 = 0;
    scn->txbf_sound_period                  = 100;
    scn->scn_promisc                        = 0;
#if ATH_SUPPORT_WRAP
    scn->mcast_bcast_echo                   = 0;
#endif
    scn->dbg.print_rate_limit               = DEFAULT_PRINT_RATE_LIMIT_VALUE;
#if ATH_DATA_TX_INFO_EN
    scn->enable_perpkt_txstats              = 0;
#endif

        return;
}

/* Suspend and unload the firmware during the last vap removal */
int ol_ath_target_stop(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn;
    struct net_device *dev;
    struct pci_dev *pcidev;
    int target_paused = TRUE;
    int idx;
    struct ieee80211_dfs_state *dfs = &ic->ic_dfs_state;

    scn =  OL_ATH_SOFTC_NET80211(ic);
    dev = scn->sc_osdev->netdev;
    pcidev = (struct pci_dev *)scn->sc_osdev->bdev;
    ic = &scn->sc_ic;
    if (atomic_read(&scn->reset_in_progress)) {
        qdf_print("Reset in progress, return\n");
        return -1;
    }

    if (scn->down_complete) {
        /*
         * Target has already been stopped
         */
        return 0;
    }

    scn->radio_attached = 0;

    atomic_inc(&scn->reset_in_progress);
#if OL_ATH_SUPPORT_LED
    scn->scn_led_blink_rate_table = NULL;
    qdf_timer_sync_cancel(&scn->scn_led_blink_timer);
    qdf_timer_sync_cancel(&scn->scn_led_poll_timer);

    if(scn->target_type == TARGET_TYPE_IPQ4019) {
        ipq4019_wifi_led(scn, LED_OFF);
    }
#endif
    ol_ath_stats_detach(ic);
    /* Suspend Target if not recovering */
    if (ic->recovery_in_progress == 0) {
        qdf_print("Suspending Target  scn=%p\n", scn);
        if (!ol_ath_suspend_target(scn, 1)) {
            u_int32_t  timeleft;
            qdf_print("waiting for target paused event from target \n");
            /* wait for the event from Target*/
            timeleft = wait_event_interruptible_timeout(scn->sc_osdev->event_queue,
                (scn->is_target_paused == TRUE),
                200);
            if(!timeleft || signal_pending(current)) {
                qdf_print("ERROR: Failed to receive target paused event scn=%p \n", scn);
                target_paused = FALSE;
            }
            /*
             * reset is_target_paused and host can check that in next time,
             * or it will always be TRUE and host just skip the waiting
             * condition, it causes target assert due to host already suspend
             */
            scn->is_target_paused = FALSE;
        }
    } else {
        scn->is_target_paused = FALSE;
    }

    hif_disable_isr(scn->hif_hdl);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    preempt_disable();

    if (scn->nss_wifi_ol_mode) {

            qdf_print("scn->radioattached %d \n", scn->radio_attached);
            osif_nss_ol_wifi_pause(scn);
            qdf_print("%s:nss wifi offload pause\n",__FUNCTION__);
            mdelay(100);

            osif_nss_ol_wifi_reset(scn, 0);
            qdf_print("nss wifi offload reset");
            mdelay(100);
    }

    preempt_enable();
#endif
    ol_ath_thermal_mitigation_detach(scn, dev);

    ol_regdmn_detach(scn->ol_regdmn_handle);

#if ATH_SUPPORT_DFS
    if (ic->recovery_in_progress == 0) {
        ieee80211_dfs_reset(ic);
        dfs_reset(ic);
    } else {
        dfs->curchan = ic->ic_curchan;
        qdf_print("bypassing DFS reset \n");
    }
#endif

    ol_ath_target_deinit(scn, 1);
    ol_ath_target_deinit_complete(scn);

    if(scn->target_type !=  TARGET_TYPE_IPQ4019) {
        pci_set_drvdata(pcidev, dev);
    }

    for (idx=0; idx<scn->num_mem_chunks; ++idx) {
#if WIFI_MEM_MANAGER_SUPPORT
        wifi_cmem_free(ic->interface_id, scn->mem_chunks[idx].req_id, (int)scn->mem_chunks[idx].vaddr);
#else
        qdf_mem_free_consistent(
                scn->qdf_dev,
                &(((struct pci_dev *)(scn->qdf_dev->drv_hdl))->dev),
                scn->mem_chunks[idx].len,
                scn->mem_chunks[idx].vaddr,
                scn->mem_chunks[idx].paddr,
                qdf_get_dma_mem_context((&(scn->mem_chunks[idx])), memctx));
#endif
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    if(scn->alloc_task_wqueue != NULL) {
        ATH_FLUSH_WQUEUE(scn->alloc_task_wqueue);
        ATH_DESTROY_WQUEUE(scn->alloc_task_wqueue);
        scn->alloc_task_wqueue = NULL;
    }
#endif

    scn->num_mem_chunks = 0;
    scn->wmi_service_ready = FALSE;
    scn->wmi_ready = FALSE;
    scn->invalid_vht160_info = FALSE;
    ol_reset_params(scn);
    ol_ath_diag_user_agent_fini(scn);
    scn->down_complete = true;
    atomic_dec(&scn->reset_in_progress);
    return 0;
}
EXPORT_SYMBOL(ol_ath_target_stop);

/* Load the firmware and enable interrupts during the first vap creation
 * or before sending any WMI command to the target.
 */
extern const struct of_device_id ath_wifi_of_match[];
#define IPQ4019_DEVICE_ID (0x12ef)
void *ol_hif_open(struct device *dev, void *bdev, void *bid,
        enum ath_hal_bus_type bus_type, bool reinit, qdf_device_t qdf_dev, void *mem);
int ol_ath_target_start(struct ol_ath_softc_net80211 *scn)
{
    struct net_device *dev;
    struct platform_device *pdev;
    struct pci_dev *pcidev;
    struct ieee80211com *ic = &scn->sc_ic;
    int idx = 0;

    if (atomic_read(&scn->reset_in_progress)) {
        qdf_print("Reset in progress, return\n");
        return -1;
    }

    if (!(scn->down_complete)) {
        /*
         * Target has already been started
         */
        return 0;
    }

    if (scn->radio_attached) {
        qdf_print("WARN: radio_attached variable is non zero\n");
    }

    pdev = (struct platform_device *)scn->sc_osdev->bdev;
    pcidev = (struct pci_dev *)scn->sc_osdev->bdev;
    dev = scn->sc_osdev->netdev;
    atomic_inc(&scn->reset_in_progress);

    if(scn->target_type == TARGET_TYPE_IPQ4019) {
	    scn->hif_hdl = ol_hif_open(&pdev->dev, pdev, (void *)scn->pdevid, HAL_BUS_TYPE_AHB, 0,scn->qdf_dev, NULL);
    } else {
	    pci_set_drvdata(pcidev, NULL);
	    scn->hif_hdl = ol_hif_open(&pcidev->dev, pdev, (void *)scn->pdevid, HAL_BUS_TYPE_PCI, 0,scn->qdf_dev, NULL);
	    pci_set_drvdata(pcidev, dev);
    }

    if (scn->hif_hdl == NULL) {
        goto fail3;
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (scn->nss_wifi_ol_mode) {
            if (osif_nss_ol_wifi_init(scn)) {
                    goto fail;
            }
    }
#endif

    if (ol_target_init(scn, false))
        goto fail;

    if (ol_target_init_complete(scn))
        goto fail;
    ol_ath_mgmt_attach(ic);
    ol_ath_stats_attach(ic);
    if (ol_ath_thermal_mitigation_attach(scn, dev))
        goto fail;

#if ATH_SUPPORT_DFS
    if (!ic->recovery_in_progress) {
        ol_if_dfs_setup(ic);
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Bypassing DFS setup \n");
    }
#endif

    ieee80211com_set_cap(ic, IEEE80211_C_WEP);
    ieee80211com_set_cap(ic, IEEE80211_C_AES);
    ieee80211com_set_cap(ic, IEEE80211_C_AES_CCM);
    ieee80211com_set_cap(ic, IEEE80211_C_CKIP);
    ieee80211com_set_cap(ic, IEEE80211_C_TKIP);
    ieee80211com_set_cap(ic, IEEE80211_C_TKIPMIC);

#if ATH_SUPPORT_WAPI
    ieee80211com_set_cap(ic, IEEE80211_C_WAPI);
#endif


#if OL_ATH_SUPPORT_LED
    if (!bypasswmi) {
#if QCA_LTEU_SUPPORT
        if (scn->lteu_support) {
            ol_gpio_config(scn, scn->scn_led_gpio, 1, WMI_GPIO_PULL_DOWN, WMI_GPIO_INTTYPE_RISING_EDGE);
        } else {
#endif /* QCA_LTEU_SUPPORT */
            if(scn->target_type == TARGET_TYPE_IPQ4019) {
                /* Do not enable LED for IPQ4019 during attach, as wifi LED will keep
                   glowing even if vaps are not created for that radio */
            } else {
                ol_gpio_config(scn, scn->scn_led_gpio, 0, 0, 0);
                ol_ath_gpio_output(scn, scn->scn_led_gpio, 1);
            }
            OS_INIT_TIMER(scn->sc_osdev, &(scn->scn_led_blink_timer), ol_ath_led_blink_timed_out, (void *)scn, QDF_TIMER_TYPE_WAKE_APPS);
            OS_INIT_TIMER(scn->sc_osdev, &(scn->scn_led_poll_timer), ol_ath_led_poll_timed_out, (void *)scn, QDF_TIMER_TYPE_WAKE_APPS);
            scn->scn_blinking = OL_BLINK_DONE;
            scn->scn_led_byte_cnt = 0;
            scn->scn_led_last_time = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
            scn->scn_led_blink_rate_table         = ol_led_blink_rate_table;
            scn->scn_led_max_blink_rate_idx = ARRAY_LENGTH(ol_led_blink_rate_table) - 1;
#if QCA_LTEU_SUPPORT
        }
#endif /* QCA_LTEU_SUPPORT */
    }
#endif /* OL_ATH_SUPPORT_LED */

    ol_ath_diag_user_agent_init(scn);
    scn->down_complete = false;
    atomic_dec(&scn->reset_in_progress);
    scn->radio_attached = 1;
    return 0;

fail:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    if(scn->alloc_task_wqueue != NULL) {
        ATH_FLUSH_WQUEUE(scn->alloc_task_wqueue);
        ATH_DESTROY_WQUEUE(scn->alloc_task_wqueue);
        scn->alloc_task_wqueue = NULL;
    }
#endif
   hif_disable_isr(scn->hif_hdl);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (scn->nss_wifi_ol_mode) {
        osif_nss_ol_wifi_pause(scn);
        qdf_print("nss wifi offload paused as %s failed\n",__FUNCTION__);

        osif_nss_ol_wifi_reset(scn, 0);
        qdf_print("nss wifi offload reset as %s failed\n", __FUNCTION__);
    }
#endif

    ol_ath_target_deinit(scn, 1);
    ol_ath_target_deinit_complete(scn);
    if(scn->target_type !=  TARGET_TYPE_IPQ4019) {
	pci_set_drvdata(pcidev, scn->sc_osdev->netdev);
    }

fail3:
    for (idx=0; idx<scn->num_mem_chunks; ++idx) {
#if WIFI_MEM_MANAGER_SUPPORT
    wifi_cmem_free(ic->interface_id, scn->mem_chunks[idx].req_id, (int)scn->mem_chunks[idx].vaddr);
#else
    qdf_mem_free_consistent(
            scn->qdf_dev,
            &(((struct pci_dev *)(scn->qdf_dev->drv_hdl))->dev),
            scn->mem_chunks[idx].len,
            scn->mem_chunks[idx].vaddr,
            scn->mem_chunks[idx].paddr,
            qdf_get_dma_mem_context((&(scn->mem_chunks[idx])), memctx));
#endif
    }
    scn->num_mem_chunks = 0;
    scn->wmi_service_ready = FALSE;
    scn->wmi_ready = FALSE;
    scn->invalid_vht160_info = FALSE;
    scn->down_complete = true;
    atomic_dec(&scn->reset_in_progress);
    return -1;
}
EXPORT_SYMBOL(ol_ath_target_start);

int
ol_ath_resume(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com     *ic;

    ic = &scn->sc_ic;
    /*
     * ignore if already resumed.
     */
    if (OS_ATOMIC_CMPXCHG(&(scn->sc_dev_enabled), 0, 1) == 1) {
    return 0;
    }
    ieee80211_stop_running(ic);

    ieee80211_start_running(ic);

    return 0;
}

int
ol_ath_suspend(struct ol_ath_softc_net80211 *scn)
{
    /*
     * ignore if already suspended;
     */
    if (OS_ATOMIC_CMPXCHG(&(scn->sc_dev_enabled), 1, 0) == 0) {
        return 0;
    }

    ieee80211_stop_running(&scn->sc_ic);

    return 0;
}

void
ol_ath_target_status_update(struct ol_ath_softc_net80211 *scn, ol_target_status status)
{
    /* target lost, host needs to recover/reattach */
    scn->target_status = status;
}

void
ol_ath_suspend_resume_attach(struct ol_ath_softc_net80211 *scn)
{
}


int
ol_ath_suspend_target(struct ol_ath_softc_net80211 *scn, int disable_target_intr)
{
    struct suspend_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.disable_target_intr = disable_target_intr;

    //Sending macid as 0 since we do not require the param
    return wmi_unified_suspend_send(scn->wmi_handle, &param, 0);
}

int
ol_ath_resume_target(struct ol_ath_softc_net80211 *scn)
{
	uint8_t retval = 0;

	if (scn->wmi_handle) {
		retval = wmi_unified_resume_send(scn->wmi_handle, 0);
	}

	return retval;
}
#ifndef A_MIN
#define A_MIN(a,b)    ((a)<(b)?(a):(b))
#endif
/*
 * ol_ath_cw_interference_handler
 *
 * Functionality of this should be the same as
 * ath_net80211_cw_interference_handler() in lmac layer of the direct attach
 * drivers. Keep this same across both.
 *
 * When the cw interference is sent from the target, kick start the scan
 * with auto channel. This is disruptive channel change. Non-discruptive
 * channel change is the responsibility of scan module.
 *
 */
static void
ol_ath_wlan_n_cw_interference_handler(struct ol_ath_softc_net80211 *scn,
                                      A_UINT32 interference_type)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic = &scn->sc_ic;
#if ATH_SUPPORT_SPECTRAL
    struct ath_spectral *spectral = ic->ic_spectral;
#endif

    /* Check if CW Interference is already been found and being handled */
    if (ic->cw_inter_found)
        return;

	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS: inteference_handler - start");

    spin_lock(&ic->ic_lock);

    /*
	 * mark this channel as cw_interference is found
     * Set the CW interference flag so that ACS does not bail out this flag
     * would be reset in ieee80211_beacon.c:ieee80211_beacon_update()
     */
    ic->cw_inter_found = 1;

    /* Before triggering the channel change, turn off the dcs until the
     * channel change completes, to avoid repeated reports.
     */
    (void)ol_ath_pdev_set_param(scn, wmi_pdev_param_dcs, 0, 0);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS channel change triggered, disabling until channel change completes\n");
    OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable);
    spin_unlock(&ic->ic_lock);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "De-authenticating all the nodes before channel change \n");
            wlan_deauth_all_stas(vap);
        }
    }

#if ATH_SUPPORT_SPECTRAL
    if (scn->scn_icm_active) {
        spin_lock(&ic->ic_lock);

        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "ICM is active, sending message to change channel with "
               "DCS flag %d\n",
               OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable));

        /* Currently, ol_ath_wlan_n_cw_interference_handler()
           is common to both CW AND WLAN interferences */
        if (interference_type == ATH_CAP_DCS_CWIM) {
            spectral_send_intf_found_msg(spectral,
                                   1,
                                   OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable));
        } else if (interference_type == ATH_CAP_DCS_WLANIM) {
            spectral_send_intf_found_msg(spectral,
                                   0,
                                   OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable));
        }
        spin_unlock(&ic->ic_lock);
    } else {
#endif /* ATH_SUPPORT_SPECTRAL */
        /* Loop through and figure the first VAP on this radio */
        /* FIXME
         * There could be some issue in mbssid mode. It does look like if
         * wlan_set_channel fails on first vap, it tries on the second vap
         * again. Given that all vaps on same radio, we may need not do this.
         * Need a test case for this. Leaving the code as it is.
         */
        TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
            if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
                if (ieee80211_vap_active_is_set(vap) &&
                      !wlan_set_channel(vap, IEEE80211_CHAN_ANY, 0)) {
                    /* ACS is done on per radio, so calling it once is
                    * good enough
                    */
                    goto done;
                }
            }
        }
        spin_lock(&ic->ic_lock);
        /*
         * reset cw_interference found flag since ACS is not triggered, so
         * it can change the channel on next CW intf detection
         */
        ic->cw_inter_found = 0;
        spin_unlock(&ic->ic_lock);

#if ATH_SUPPORT_SPECTRAL
    }
#endif /* ATH_SUPPORT_SPECTRAL */

#if ATH_SUPPORT_SPECTRAL
    if (!(scn->scn_icm_active)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS: %s ACS Trigger failed ", __func__);
    }
#else
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS: %s ACS Trigger failed ", __func__);
#endif /* ATH_SUPPORT_SPECTRAL */

    /* Should not come here (if ICM is not active), something is not right, hope
     * something better happens next time the flag is set
     */

done:
	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS: %s interference_handling is complete...", __func__);
}

inline static void
wlan_dcs_im_copy_stats(wmi_host_dcs_im_tgt_stats_t *prev_stats, wmi_host_dcs_im_tgt_stats_t *curr_stats)
{
	/* right now no other actions are required beyond memcopy, if
	 * rquired the rest of the code would follow
	 */
	OS_MEMCPY(prev_stats, curr_stats, sizeof(wmi_host_dcs_im_tgt_stats_t));
}

inline static void
wlan_dcs_im_print_stats(wmi_host_dcs_im_tgt_stats_t *prev_stats, wmi_host_dcs_im_tgt_stats_t *curr_stats)
{
	/* debug, dump all received stats first */
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "tgt_curr/tsf,%u", curr_stats->reg_tsf32);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/last_ack_rssi,%u", curr_stats->last_ack_rssi);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/tx_waste_time,%u", curr_stats->tx_waste_time);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/dcs_rx_time,%u", curr_stats->rx_time);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/listen_time,%u", curr_stats->mib_stats.listen_time);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/tx_frame_cnt,%u", curr_stats->mib_stats.reg_tx_frame_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/rx_frame_cnt,%u", curr_stats->mib_stats.reg_rx_frame_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/rxclr_cnt,%u", curr_stats->mib_stats.reg_rxclr_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/reg_cycle_cnt,%u", curr_stats->mib_stats.reg_cycle_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/rxclr_ext_cnt,%u", curr_stats->mib_stats.reg_rxclr_ext_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/ofdm_phyerr_cnt,%u", curr_stats->mib_stats.reg_ofdm_phyerr_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_curr/cck_phyerr_cnt,%u", curr_stats->mib_stats.reg_cck_phyerr_cnt);

	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "tgt_prev/tsf,%u", prev_stats->reg_tsf32);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/last_ack_rssi,%u", prev_stats->last_ack_rssi);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/tx_waste_time,%u", prev_stats->tx_waste_time);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/rx_time,%u", prev_stats->rx_time);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/listen_time,%u", prev_stats->mib_stats.listen_time);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/tx_frame_cnt,%u", prev_stats->mib_stats.reg_tx_frame_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/rx_frame_cnt,%u", prev_stats->mib_stats.reg_rx_frame_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/rxclr_cnt,%u", prev_stats->mib_stats.reg_rxclr_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/reg_cycle_cnt,%u", prev_stats->mib_stats.reg_cycle_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/rxclr_ext_cnt,%u", prev_stats->mib_stats.reg_rxclr_ext_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/ofdm_phyerr_cnt,%u", prev_stats->mib_stats.reg_ofdm_phyerr_cnt);
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",tgt_prev/cck_phyerr_cnt,%u", prev_stats->mib_stats.reg_cck_phyerr_cnt);
}

/*
 * reg_xxx - All the variables are contents of the corresponding
 *  		register contents
 * xxx_delta - computed difference between previous cycle and c
 * 		    current cycle
 * reg_xxx_cu	- Computed channel utillization in %,
 *  		computed through register statistics
 *
 * FIXME ideally OL and non-OL layers can re-use the same code.
 * But this is done differently between OL and non-OL paths.
 * We may need to rework this completely for both to work with single
 * piece of code. The non-OL path also need lot of rework. All
 * stats need to be taken to UMAC layer. That seems to be too
 * much of work to do at this point of time. Right now host code
 * is limited to one below function, and this function alone
 * need to go UMAC. Given that function is small, tend to keep
 * only here here. If this gets any bigger we shall try doing it
 * in umac, and merge entire code ( ol and non-ol to umac ).
 */
static void
ol_ath_wlan_interference_handler(ol_scn_t scn,
                                 wmi_host_dcs_im_tgt_stats_t *curr_stats,
                                 A_UINT32 interference_type)
{
	wmi_host_dcs_im_tgt_stats_t *prev_stats;

	u_int32_t reg_tsf_delta = 0;                /* prev-tsf32  - curr-tsf32 */
	u_int32_t rxclr_delta = 0;                  /* prev-RXCLR - curr-RXCLR */
	u_int32_t rxclr_ext_delta = 0;              /* prev-RXEXTCLR - curreent RXEXTCLR, most of the time this is zero, chip issue ?? */
	u_int32_t cycle_count_delta = 0;            /* prev CCYCLE - curr CCYCLE */
	u_int32_t tx_frame_delta = 0;               /* prev TFCT - curr TFCNT */
	u_int32_t rx_frame_delta = 0;               /* prev RFCNT - curr RFCNT */
	u_int32_t reg_total_cu = 0; 				/* total channel utilization in %*/
	u_int32_t reg_tx_cu = 0;					/* transmit channel utilization in %*/
    u_int32_t reg_rx_cu = 0;					/* receive channel utilization in %*/
	u_int32_t reg_unused_cu = 0;                /* unused channel utillization */
	u_int32_t rx_time_cu=0;						/* computed rx time*/
	u_int32_t reg_ofdm_phyerr_delta = 0;		/* delta ofdm errors */
	u_int32_t reg_cck_phyerr_delta = 0;			/* delta cck errors*/
	u_int32_t reg_ofdm_phyerr_cu = 0;			/* amount utilization by ofdm errors*/
	u_int32_t ofdm_phy_err_rate = 0;			/* rate at which ofdm errors are seen*/
	u_int32_t cck_phy_err_rate=0;				/* rate at which cck errors are seen*/
	u_int32_t max_phy_err_rate = 0;
    u_int32_t max_phy_err_count = 0;
	u_int32_t total_wasted_cu = 0;
	u_int32_t wasted_tx_cu = 0;
	u_int32_t tx_err = 0;
	int too_many_phy_errors = 0;

	if (!scn || !curr_stats) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDCS: scn is NULL\n");
		return;
	}

    prev_stats =  &scn->scn_dcs.scn_dcs_im_stats.prev_dcs_im_stats;

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        wlan_dcs_im_print_stats(prev_stats, curr_stats);
    }

    /* counters would have wrapped. Ideally we should be able to figure this
     * out, but we never know how many times counters wrapped. just ignore
     */
	if ((curr_stats->mib_stats.listen_time <= 0) ||
        (curr_stats->reg_tsf32 <= prev_stats->reg_tsf32)) {

		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDCS: ignoring due to negative TSF value\n");
        }
        /* copy the current stats to previous stats for next run */
		wlan_dcs_im_copy_stats(prev_stats, curr_stats);
		return;
	}

	reg_tsf_delta = curr_stats->reg_tsf32 - prev_stats->reg_tsf32;

	/* do nothing if current stats are not seeming good, probably
	 * a reset happened on chip, force cleared
	 */
	if (prev_stats->mib_stats.reg_rxclr_cnt > curr_stats->mib_stats.reg_rxclr_cnt) {
		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDCS: ignoring due to negative rxclr count\n");
        }

        /* copy the current stats to previous stats for next run */
		wlan_dcs_im_copy_stats(prev_stats, curr_stats);
		return;
	}

	rxclr_delta = curr_stats->mib_stats.reg_rxclr_cnt - prev_stats->mib_stats.reg_rxclr_cnt;
	rxclr_ext_delta = curr_stats->mib_stats.reg_rxclr_ext_cnt -
								prev_stats->mib_stats.reg_rxclr_ext_cnt;
	tx_frame_delta = curr_stats->mib_stats.reg_tx_frame_cnt -
								prev_stats->mib_stats.reg_tx_frame_cnt;

	rx_frame_delta = curr_stats->mib_stats.reg_rx_frame_cnt -
								prev_stats->mib_stats.reg_rx_frame_cnt;

	cycle_count_delta = curr_stats->mib_stats.reg_cycle_cnt -
								prev_stats->mib_stats.reg_cycle_cnt;

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",rxclr_delta,%u,rxclr_ext_delta,%u,tx_frame_delta,%u,rx_frame_delta,%u,cycle_count_delta,%u",
                rxclr_delta , rxclr_ext_delta , tx_frame_delta,
                rx_frame_delta , cycle_count_delta );
    }

    if(0 == (cycle_count_delta >>8)) {
        wlan_dcs_im_copy_stats(prev_stats, curr_stats);
        if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE))
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " cycle count NULL---Investigate--\n");
        return;
    }

	/* total channel utiliztaion is the amount of time RXCLR is
	 * counted. RXCLR is counted, when 'RX is NOT clear', please
	 * refer to mac documentation. It means either TX or RX is ON
     *
     * Why shift by 8 ? after multiplication it could overflow. At one
     * second rate, neither cycle_count_celta, nor the tsf_delta would be
     * zero after shift by 8 bits
	 */
	reg_total_cu = ((rxclr_delta >> 8) * 100) / (cycle_count_delta >>8);
	reg_tx_cu = ((tx_frame_delta >> 8 ) * 100) / (cycle_count_delta >> 8);
	reg_rx_cu = ((rx_frame_delta >> 8 ) * 100) / (cycle_count_delta >> 8);
	rx_time_cu = ((curr_stats->rx_time >> 8) * 100 ) / (reg_tsf_delta >> 8);

    /**
     * Amount of the time AP received cannot go higher than the receive
     * cycle count delta. If at all it is, there should have been a
     * compution error, ceil it to receive_cycle_count_diff
     */
	if (rx_time_cu > reg_rx_cu) {
		rx_time_cu = reg_rx_cu;
	}

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",reg_total_cu,%u,reg_tx_cu,%u,reg_rx_cu,%u,rx_time_cu,%u",
                    reg_total_cu, reg_tx_cu, reg_rx_cu, rx_time_cu);
    }

	/* Unusable channel utilization is amount of time that we
	 * spent in backoff or waiting for other transmit/receive to
	 * complete. If there is interference it is more likely that
	 * we overshoot the limit. In case of multiple stations, we
	 * still see increased channel utilization.  This assumption may
	 * not be true for the VOW scenario where either multicast or
	 * unicast-UDP is used ( mixed traffic would still cause high
	 * channel utilization).
     */
	wasted_tx_cu = ((curr_stats->tx_waste_time >> 8) * 100 ) / (reg_tsf_delta >> 8);

    /**
     * transmit channel utilization cannot go higher than the amount of time
     * wasted, if so cap the wastage to transmit channel utillzation. This
     * could happen to compution error.
     */
	if (reg_tx_cu < wasted_tx_cu) {
		wasted_tx_cu = reg_tx_cu;
	}

	tx_err = (reg_tx_cu  && wasted_tx_cu) ? (wasted_tx_cu * 100 )/reg_tx_cu : 0;

    /**
     * The below actually gives amount of time we are not using, or the
     * interferer is active.
     * rx_time_cu is what computed receive time *NOT* rx_cycle_count
     * rx_cycle_count is our receive+interferer's transmit
     * un-used is really total_cycle_counts -
     *      (our_rx_time(rx_time_cu)+ our_receive_time)
     */
	reg_unused_cu = (reg_total_cu >= (reg_tx_cu + rx_time_cu)) ?
							(reg_total_cu - (reg_tx_cu + rx_time_cu)) : 0;

    /* if any retransmissions are there, count them as wastage
     */
	total_wasted_cu = reg_unused_cu + wasted_tx_cu;

	/* check ofdm and cck errors */
    if (unlikely(curr_stats->mib_stats.reg_ofdm_phyerr_cnt  <
            prev_stats->mib_stats.reg_ofdm_phyerr_cnt)) {
        reg_ofdm_phyerr_delta = curr_stats->mib_stats.reg_ofdm_phyerr_cnt ;
    } else {
        reg_ofdm_phyerr_delta = curr_stats->mib_stats.reg_ofdm_phyerr_cnt -
                                    prev_stats->mib_stats.reg_ofdm_phyerr_cnt;
    }

	if (unlikely(curr_stats->mib_stats.reg_cck_phyerr_cnt  <
            prev_stats->mib_stats.reg_cck_phyerr_cnt)) {
        reg_cck_phyerr_delta = curr_stats->mib_stats.reg_cck_phyerr_cnt;
    } else {
        reg_cck_phyerr_delta = curr_stats->mib_stats.reg_cck_phyerr_cnt -
                                    prev_stats->mib_stats.reg_cck_phyerr_cnt;
    }

	/* add the influence of ofdm phy errors to the wasted channel
	 * utillization, this computed through time wasted in errors,
	 */
	reg_ofdm_phyerr_cu = reg_ofdm_phyerr_delta * scn->scn_dcs.phy_err_penalty ;
	total_wasted_cu += (reg_ofdm_phyerr_cu > 0) ?  (((reg_ofdm_phyerr_cu >> 8) * 100) / (reg_tsf_delta >> 8)) : 0;

	ofdm_phy_err_rate = (curr_stats->mib_stats.reg_ofdm_phyerr_cnt * 1000) /
                                curr_stats->mib_stats.listen_time;
	cck_phy_err_rate = (curr_stats->mib_stats.reg_cck_phyerr_cnt * 1000) /
                                curr_stats->mib_stats.listen_time;

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",reg_unused_cu,%u,reg_ofdm_phyerr_delta,%u,reg_cck_phyerr_delta,%u,reg_ofdm_phyerr_cu,%u",
                    reg_unused_cu , reg_ofdm_phyerr_delta , reg_cck_phyerr_delta , reg_ofdm_phyerr_cu);
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",total_wasted_cu,%u,ofdm_phy_err_rate,%u,cck_phy_err_rate,%u",
                    total_wasted_cu , ofdm_phy_err_rate , cck_phy_err_rate );
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",new_unused_cu,%u,reg_ofdm_phy_error_cu,%u\n",
                reg_unused_cu, (curr_stats->mib_stats.reg_ofdm_phyerr_cnt*100)/
                                        curr_stats->mib_stats.listen_time);
    }

	/* check if the error rates are higher than the thresholds*/
	max_phy_err_rate = MAX(ofdm_phy_err_rate, cck_phy_err_rate);

	max_phy_err_count = MAX(curr_stats->mib_stats.reg_ofdm_phyerr_cnt,
                                curr_stats->mib_stats.reg_cck_phyerr_cnt);

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",max_phy_err_rate,%u, max_phy_err_count,%u",max_phy_err_rate , max_phy_err_count);
    }

	if (((max_phy_err_rate >= scn->scn_dcs.phy_err_threshold) &&
				(max_phy_err_count > scn->scn_dcs.phy_err_threshold)) ||
         (curr_stats->phyerr_cnt > scn->scn_dcs.radar_err_threshold)) {
		too_many_phy_errors = 1;
	}

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL)) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDCS: total_cu %u ,tx_cu %u ,rx_cu %u ,rx_time_cu %u, unused cu %u ",reg_total_cu, reg_tx_cu, reg_rx_cu, rx_time_cu, reg_unused_cu);
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDCS: phyerr %u ,total_wasted_cu %u ,phyerror_cu %u ,wasted_cu %u, reg_tx_cu %u ,reg_rx_cu %u",too_many_phy_errors, total_wasted_cu, reg_ofdm_phyerr_cu, wasted_tx_cu, reg_tx_cu, reg_rx_cu);
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nDCS: tx_err %u",tx_err);
	}

	if (reg_unused_cu >= scn->scn_dcs.coch_intr_thresh) {
		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt+=2; /* quickly reach to decision*/
	} else if (too_many_phy_errors &&
			   ((total_wasted_cu > scn->scn_dcs.coch_intr_thresh) &&
					(reg_tx_cu + reg_rx_cu) > scn->scn_dcs.user_max_cu)){ /* removed tx_err check here */
		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt++;
	}

	if (scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt >= scn->scn_dcs.intr_detection_threshold) {

        if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s interference threshould exceeded\n", __func__);
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",unused_cu,%u,too_any_phy_errors,%u,total_wasted_cu,%u,reg_tx_cu,%u,reg_rx_cu,%u\n",
                    reg_unused_cu, too_many_phy_errors, total_wasted_cu,reg_tx_cu, reg_rx_cu);
        }

		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt = 0;
		scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt = 0;
        /* once the interference is detected, change the channel, as on
         * today this is common routine for wirelesslan and non-wirelesslan
         * interference. Name as such kept the same because of the DA code,
         * which is using the same function.
         */
		ol_ath_wlan_n_cw_interference_handler(scn, interference_type);
	} else if (!scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt ||
				scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt >= scn->scn_dcs.intr_detection_window) {
		scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt = 0;
		scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt = 0;
	}

	/* count the current run too*/
	scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt++;

    /* copy the stats for next cycle */
	wlan_dcs_im_copy_stats(prev_stats, curr_stats);

    if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ",intr_count,%u,sample_count,%d\n",scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt,scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt);
    }
}

/*
 * ol_ath_dcs_interference_handler
 *
 * There are two different interference types can be reported by the
 * target firmware. Today either that is wireless interference or
 * could be a non-wireless lan interference. All of these are reported
 * WMI message.
 *
 * Message is of type wmi_dcs_interence_type_t
 *
 */
static int
ol_ath_dcs_interference_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    struct ieee80211com *ic = &scn->sc_ic;
    uint32_t interference_type;
    periodic_chan_stats_t new_stats;
    periodic_chan_stats_t *prev_stats = NULL;
    wmi_host_dcs_im_tgt_stats_t   wlan_stat;

    /* Extract interference type and periodic channel stats */
    wmi_extract_dcs_interference_type(scn->wmi_handle, data, &interference_type);
    wmi_extract_dcs_im_tgt_stats(scn->wmi_handle, data, &wlan_stat);

    /* This event is extended to provide periodic channel stats to user
     * space irrespective of DCS eneble or disable.
     * update periodic stats before handling DCS.
     */
    if (interference_type == ATH_CAP_DCS_WLANIM) {
        new_stats.tx_frame_count = wlan_stat.mib_stats.reg_tx_frame_cnt;
        new_stats.rx_frame_count = wlan_stat.mib_stats.reg_rx_frame_cnt;
        new_stats.rx_clear_count = wlan_stat.mib_stats.reg_rxclr_cnt;
        new_stats.cycle_count = wlan_stat.mib_stats.reg_cycle_cnt;
        new_stats.my_bss_rx_cycle_count = wlan_stat.my_bss_rx_cycle_count;

        /* update noise floor information */
        scn->chan_nf = wlan_stat.chan_nf;

        prev_stats = &scn->scn_dcs.chan_stats;

        /* process channel stats first*/
        if (!wlan_scan_in_progress_ic(ic)) {
            /* During scan our hardware and software counters keep incrementing
             * although they are tracking the stats of foreign channel.
             * Don't send periodic home channel stats while scan is in progress.
             */
            ol_chan_stats_event(ic, prev_stats, &new_stats);
            /* Update the counter vauses with latest one */
            scn->scn_dcs.chan_stats = new_stats;
        } else {
            ol_ath_invalidate_channel_stats(ic);
        }
    }

    /* do not handle any thing if host is in disabled state
     * This shall not happen, provide extra safty for against any delays
     * causing any kind of races.
     */
    if (!(OL_IS_DCS_RUNNING(scn->scn_dcs.dcs_enable))) {
        return 0;
    }
	switch (interference_type) {
	case ATH_CAP_DCS_CWIM: /* cw interferecne*/
		if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & ATH_CAP_DCS_CWIM) {
			ol_ath_wlan_n_cw_interference_handler(scn,
                                                  interference_type);
		}
		break;
	case ATH_CAP_DCS_WLANIM: /* wlan interference stats*/
		if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & ATH_CAP_DCS_WLANIM) {
			ol_ath_wlan_interference_handler(scn,
                                             &wlan_stat,
                                             interference_type);
		}
		break;
	default:
		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL)) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DCS: unidentified interference type reported");
        }
		break;
	}
    return 0;
}

int
ol_ath_periodic_chan_stats_config (ol_scn_t scn,
                                        bool enable,
                                        u_int32_t stats_period)
{
	struct periodic_chan_stats_params param;

	qdf_mem_set(&param, sizeof(param), 0);
	if (!scn || !(scn->periodic_chan_stats)) {
		return -EINVAL;
  	}
  	param.stats_period = stats_period;
  	param.enable = enable;
  	return wmi_unified_send_periodic_chan_stats_config_cmd(scn->wmi_handle,
			  &param);
}

#define TPC_TABLE_TYPE_CDD  0
#define TPC_TABLE_TYPE_STBC 1
#define TPC_TABLE_TYPE_TXBF 2

u_int8_t
tpc_config_get_rate_tpc(wmi_host_pdev_tpc_config_event *ev, u_int32_t rate_idx, u_int32_t num_chains, u_int8_t rate_code, u_int8_t type)
{
    u_int8_t tpc;
    u_int8_t num_streams;
    u_int8_t preamble;
    u_int8_t chain_idx;

    num_streams = 1 + AR600P_GET_HW_RATECODE_NSS(rate_code);
    preamble = AR600P_GET_HW_RATECODE_PREAM(rate_code);
    chain_idx = num_chains - 1;

    /*
     * find TPC based on the target power for that rate and the maximum
     * allowed regulatory power based on the number of tx chains.
     */
    tpc = A_MIN(ev->ratesArray[rate_idx], ev->maxRegAllowedPower[chain_idx]);

    if (ev->numTxChain > 1) {
        /*
         * Apply array gain factor for non-cck frames and when
         * num of chains used is more than the number of streams
         */
        if (preamble != AR600P_HW_RATECODE_PREAM_CCK) {
            u_int8_t stream_idx;

            stream_idx = num_streams - 1;
            if (type == TPC_TABLE_TYPE_STBC) {
                if (num_chains > num_streams) {
                    tpc = A_MIN(tpc, ev->maxRegAllowedPowerAGSTBC[chain_idx - 1][stream_idx]);
                }
            } else if (type == TPC_TABLE_TYPE_TXBF) {
                if (num_chains > num_streams) {
                    tpc = A_MIN(tpc, ev->maxRegAllowedPowerAGTXBF[chain_idx - 1][stream_idx]);
                }
            } else {
                if (num_chains > num_streams) {
                    tpc = A_MIN(tpc, ev->maxRegAllowedPowerAGCDD[chain_idx - 1][stream_idx]);
                }
            }
        }
    }

    return tpc;
}


void
tpc_config_disp_tables(wmi_host_pdev_tpc_config_event *ev, u_int8_t *rate_code, u_int16_t *pream_table, u_int8_t type)
{
    u_int32_t i, j;
    u_char table_str[3][5] =  {
        "CDD ",
        "STBC",
        "TXBF"
    };
    u_char pream_str[8][6] = {
        "CCK  ",
        "OFDM ",
        "HT20 ",
        "HT40 ",
        "VHT20",
        "VHT40",
        "VHT80",
        "HTDUP"
    };
    u_int32_t pream_idx;
    u_int8_t tpc[IEEE80211_MAX_TX_CHAINS];
    switch (type) {
        case TPC_TABLE_TYPE_CDD:
            if (!(ev->flags & WMI_HOST_TPC_CONFIG_EVENT_FLAG_TABLE_CDD)) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s : CDD not supported \n",__func__));
                return;
            }
            break;
        case TPC_TABLE_TYPE_STBC:
            if (!(ev->flags & WMI_HOST_TPC_CONFIG_EVENT_FLAG_TABLE_STBC)) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s : STBC not supported \n",__func__));
                return;
            }
            break;
        case TPC_TABLE_TYPE_TXBF:
            if (!(ev->flags & WMI_HOST_TPC_CONFIG_EVENT_FLAG_TABLE_TXBF)) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s : TXBF not supported \n",__func__));
                return;
            }
            break;
        default:
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s : Invalid type %d \n",__func__, type));
            return;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("**************** %s POWER TABLE ****************\n",table_str[type])) ;
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("**************************************************\n"));

    pream_idx = 0;
    for(i = 0;i < ev->rateMax; i++) {
	    char tpc_values[IEEE80211_MAX_TX_CHAINS * 20] = "";
	    char buff[20] = "";

	    if (i == pream_table[pream_idx]) {
		    pream_idx++;
	    }

	    for(j = 0; j < IEEE80211_MAX_TX_CHAINS; j++) {

		    if(j < ev->numTxChain) {
			    tpc[j] = tpc_config_get_rate_tpc(ev, i, j + 1, rate_code[i], type);
			    snprintf(buff, sizeof(buff), "%8d ", tpc[j]);
			    strlcat(tpc_values, buff, sizeof(tpc_values));
		    }
		    else {
			    break;
		    }

	    }
	    AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%8d %s 0x%2x %s\n", i, pream_str[pream_idx], rate_code[i], tpc_values));
    }
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("**************************************************\n"));

    return;
}

int
ol_ath_pdev_caldata_version_check_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_pdev_check_cal_version_event cal, *calInfo = &cal;

    if (wmi_extract_pdev_caldata_version_check_ev_param(scn->wmi_handle, data, calInfo)) {
        return -1;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("****************** CAl DATA Version Details ********************\n"));
    if (calInfo->cal_ok != NO_FEATURE){
        qdf_print("Current Meta Cal Version               : 0x%x \n",calInfo->software_cal_version);

#ifdef BIG_ENDIAN_HOST
        {
            int i;
            u_int32_t *destp, *srcp;
            srcp = (u_int32_t *)&calInfo->board_mcn_detail[0];
            destp = (u_int32_t *)&calInfo->board_mcn_detail[0];
            for(i=0; i < (roundup(WMI_BOARD_MCN_STRING_BUF_SIZE, sizeof(u_int32_t))/4); i++) {
                *destp = le32_to_cpu(*srcp);
                destp++; srcp++;
            }
        }
#endif
        if (calInfo->board_mcn_detail[WMI_BOARD_MCN_STRING_BUF_SIZE - 1] != '\0' ) {
            calInfo->board_mcn_detail[WMI_BOARD_MCN_STRING_BUF_SIZE - 1] = '\0' ;
        }
        qdf_print("Board (MCN : %s) Cal Version           : 0x%x \n",calInfo->board_mcn_detail, calInfo->board_cal_version);
        if (calInfo->cal_ok == CALIBRATION_OK){
            qdf_print("Calibration Status: OK \n");
        } else { /* calInfo->cal_ok  CALIBRATION_NOT_OK */
            qdf_print("Calibration Status: NOT OK \n");
        }
        qdf_print("Note: Please cross check board's MCN \n");
    } else {
        qdf_print("Board was not calibrated with this feature \n");
    }
    return 0;
}

int
ol_ath_pdev_tpc_config_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_pdev_tpc_config_event event, *ev = &event;
    u_int32_t i, j;
    u_int8_t rate_code[200];
    u_int16_t pream_table[10];
    u_int8_t rate_idx;
    u_int32_t pream_idx;

    if (wmi_extract_pdev_tpc_config_ev_param(scn->wmi_handle, data, ev)) {
        return -1;
    }

#ifdef BIG_ENDIAN_HOST
    {
        /*
         * Target is in little endian, copy engine interface will
         * swap at the dword boundary. Re-swap the byte stream
         * arrays
         */
        u_int32_t *destp, *srcp;
        u_int32_t len;

        srcp = (u_int32_t *)&ev->maxRegAllowedPower[0];
        destp = (u_int32_t *)&ev->maxRegAllowedPower[0];
        len = sizeof(wmi_host_pdev_tpc_config_event) - offsetof(wmi_host_pdev_tpc_config_event, maxRegAllowedPower);
        for(i=0; i < (roundup(len, sizeof(u_int32_t))/4); i++) {
            *destp = le32_to_cpu(*srcp);
            destp++; srcp++;
        }
    }
#endif

    /* Create the rate code table based on the chains supported */
    rate_idx = 0;
    pream_idx = 0;

    /* Fill CCK rate code */
    for (i=0;i<4;i++) {
        rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(i, 0, AR600P_HW_RATECODE_PREAM_CCK);
        rate_idx++;
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    /* Fill OFDM rate code */
    for (i=0;i<8;i++) {
        rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(i, 0, AR600P_HW_RATECODE_PREAM_OFDM);
        rate_idx++;
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    /* Fill HT20 rate code */
    for (i=0;i<ev->numTxChain;i++) {
        for (j=0;j<8;j++) {
            rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(j, i, AR600P_HW_RATECODE_PREAM_HT);
            rate_idx++;
        }
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    /* Fill HT40 rate code */
    for (i=0;i<ev->numTxChain;i++) {
        for (j=0;j<8;j++) {
            rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(j, i, AR600P_HW_RATECODE_PREAM_HT);
            rate_idx++;
        }
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    /* Fill VHT20 rate code */
    for (i=0;i<ev->numTxChain;i++) {
        for (j=0;j<10;j++) {
            rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(j, i, AR600P_HW_RATECODE_PREAM_VHT);
            rate_idx++;
        }
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    /* Fill VHT40 rate code */
    for (i=0;i<ev->numTxChain;i++) {
        for (j=0;j<10;j++) {
            rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(j, i, AR600P_HW_RATECODE_PREAM_VHT);
            rate_idx++;
        }
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    /* Fill VHT80 rate code */
    for (i=0;i<ev->numTxChain;i++) {
        for (j=0;j<10;j++) {
            rate_code[rate_idx] = AR600P_ASSEMBLE_HW_RATECODE(j, i, AR600P_HW_RATECODE_PREAM_VHT);
            rate_idx++;
        }
    }
    pream_table[pream_idx] = rate_idx;
    pream_idx++;

    rate_code[rate_idx++] = AR600P_ASSEMBLE_HW_RATECODE(0, 0, AR600P_HW_RATECODE_PREAM_CCK);
    rate_code[rate_idx++] = AR600P_ASSEMBLE_HW_RATECODE(0, 0, AR600P_HW_RATECODE_PREAM_OFDM);
    rate_code[rate_idx++] = AR600P_ASSEMBLE_HW_RATECODE(0, 0, AR600P_HW_RATECODE_PREAM_CCK);
    rate_code[rate_idx++] = AR600P_ASSEMBLE_HW_RATECODE(0, 0, AR600P_HW_RATECODE_PREAM_OFDM);
    rate_code[rate_idx++] = AR600P_ASSEMBLE_HW_RATECODE(0, 0, AR600P_HW_RATECODE_PREAM_OFDM);

    /* use 0xFFFF to indicate end of table */
    pream_table[pream_idx] = 0xFFFF;

    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("**************************************************\n"));
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("TPC Config for channel %4d mode %2d \n", ev->chanFreq, ev->phyMode));
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("**************************************************\n"));

    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("CTL           = 0x%2x   Reg. Domain           = %2d \n", ev->ctl, ev->regDomain));
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Antenna Gain  = %2d     Reg. Max Antenna Gain = %2d \n", ev->twiceAntennaGain, ev->twiceAntennaReduction));
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Power Limit   = %2d     Reg. Max Power        = %2d \n", ev->powerLimit, ev->twiceMaxRDPower));
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Num tx chains = %2d    Num  Supported Rates  = %2d \n", ev->numTxChain, ev->rateMax));
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("**************************************************\n"));

    tpc_config_disp_tables(ev, rate_code, pream_table, TPC_TABLE_TYPE_CDD);
    tpc_config_disp_tables(ev, rate_code, pream_table, TPC_TABLE_TYPE_STBC);
    tpc_config_disp_tables(ev, rate_code, pream_table, TPC_TABLE_TYPE_TXBF);


    return 0;
}

int
ol_ath_packet_power_info_get(struct ol_ath_softc_net80211 *scn, u_int16_t rate_flags, u_int16_t nss, u_int16_t preamble, u_int16_t hw_rate)
{
    struct packet_power_info_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.rate_flags = rate_flags;
    param.nss = nss;
    param.preamble = preamble;
    param.hw_rate = hw_rate;

    return wmi_unified_packet_power_info_get_cmd_send(scn->wmi_handle, &param);
}

int
ol_gpio_config(struct ol_ath_softc_net80211 *scn, u_int32_t gpio_num, u_int32_t input,
                        u_int32_t pull_type, u_int32_t intr_mode)
{
    struct gpio_config_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.pull_type = pull_type;
    param.gpio_num = gpio_num;
    param.input = input;
    param.intr_mode = intr_mode;

    return wmi_unified_gpio_config_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_gpio_output(struct ol_ath_softc_net80211 *scn, u_int32_t gpio_num, u_int32_t set)
{
    struct gpio_output_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.gpio_num = gpio_num;
    param.set = set;

    return wmi_unified_gpio_output_cmd_send(scn->wmi_handle, &param);
}

int
ol_ath_btcoex_duty_cycle(struct ol_ath_softc_net80211 *scn, u_int32_t period, u_int32_t duration)
{
    struct btcoex_cfg_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.period = period;
    param.wlan_duration = duration ;
    param.btcoex_param_flags = WMI_HOST_BTCOEX_PARAM_FLAGS_DUTY_CYCLE_BIT;
    return wmi_unified_send_btcoex_duty_cycle_cmd(scn->wmi_handle, &param);
}

int
ol_ath_btcoex_wlan_priority(struct ol_ath_softc_net80211 *scn, u_int32_t wlan_priority)
{
    struct btcoex_cfg_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.btcoex_wlan_priority_bitmap = wlan_priority;
    param.btcoex_param_flags = WMI_HOST_BTCOEX_PARAM_FLAGS_WLAN_PRIORITY_BITMAP_BIT;
    return wmi_unified_send_btcoex_wlan_priority_cmd(scn->wmi_handle, &param);
}

int
ol_ath_coex_ver_cfg(struct ol_ath_softc_net80211 *scn, void *cfg)
{
	coex_ver_cfg_t param;

	qdf_mem_set(&param, sizeof(param), 0);
	param.coex_version = scn->coex_version;
	if (scn->coex_version == 4) {
		u_int32_t ss_id = *((u_int32_t *) cfg);
		coex_config_v4 *coex_cfg_v4 = (coex_config_v4 *) param.config_buf;

		coex_cfg_v4->coex_priority_0_ss_id = (ss_id & 0x000000FF);
		coex_cfg_v4->coex_priority_1_ss_id = (ss_id & 0x0000FF00) >> 8;
		coex_cfg_v4->coex_priority_2_ss_id = (ss_id & 0x00FF0000) >> 16;
		coex_cfg_v4->coex_priority_3_ss_id = (ss_id & 0xFF000000) >> 24;
		param.length = 4;
	}

	return wmi_unified_send_coex_ver_cfg_cmd(scn->wmi_handle, &param);
}

int
ol_ath_gpio_input_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    uint32_t gpio_num;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif

    if (wmi_extract_gpio_input_ev_param(scn->wmi_handle, data, &gpio_num)) {
        return -1;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n%s: GPIO Input Event on Num %d\n", __func__, gpio_num);

#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
    if (acfg_event == NULL)
        return 0;

    acfg_event->gpio_num = gpio_num;
    acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_GPIO_INPUT, acfg_event);
    kfree(acfg_event);
#endif
    return 0;
}


#if 1
#define MAX_NUM_CHAINS 4
int
ol_ath_nf_dbr_dbm_info_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    u_int32_t i, j;
    wmi_host_pdev_nfcal_power_all_channels_event event, *ev = &event;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif
    if (wmi_extract_nfcal_power_ev_param(scn->wmi_handle, data, ev)) {
        return -1;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "nfdBr\tnfdBm\n");
    for(j=0; j<4; j++)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Freq=%d \n", ev->freqNum[j]);
        for(i=0; i<MAX_NUM_CHAINS; i++)
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%d\t%d\n", (int8_t)ev->nfdBr[j*4+i], (int8_t)ev->nfdBm[j*4+i]);
    }
#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
    if (acfg_event == NULL)
        return 0;

    memcpy(&acfg_event->nf_dbr_dbm, ev, sizeof(wmi_host_pdev_nfcal_power_all_channels_event));
    acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_NF_DBR_DBM_INFO, acfg_event);
    kfree(acfg_event);
#endif

    return 0;
}

#undef MAX_NUM_CHAINS
#endif

int
ol_ath_packet_power_info_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_pdev_tpc_event event, *ev = &event;
#if UMAC_SUPPORT_ACFG
    acfg_event_data_t *acfg_event = NULL;
#endif
    if (wmi_extract_pdev_tpc_ev_param(scn->wmi_handle, data, ev)) {
        return -1;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Packet Power = %d\n", ((int16_t)ev->tpc[0]));

#if UMAC_SUPPORT_ACFG
    acfg_event = (acfg_event_data_t *)kmalloc(sizeof(acfg_event_data_t), GFP_ATOMIC);
    if (acfg_event == NULL)
        return 0;

    memcpy(&(acfg_event->packet_power), ev, sizeof(wmi_host_pdev_tpc_event));
    acfg_send_event(scn->sc_osdev->netdev, scn->sc_osdev, WL_EVENT_TYPE_PACKET_POWER_INFO, acfg_event);
    kfree(acfg_event);
#endif
    return 0;
}

int
ol_ath_generic_buffer_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_pdev_generic_buffer_event event, *ev = &event;
#ifdef BIG_ENDIAN_HOST
    u_int8_t i;
#endif
    if (wmi_extract_pdev_generic_buffer_ev_param(scn->wmi_handle, data, ev)) {
        return -1;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Generic buffer received: type=%d len=%d frag_id=%d, more_frag=%d\n",
            ev->buf_type, ev->buf_len, ev->frag_id, ev->more_frag);

#ifdef BIG_ENDIAN_HOST
    {
        u_int32_t *destp, *srcp;
        u_int32_t len;

        srcp = &ev->buf_info[0];
        destp = &ev->buf_info[0];
        len = ev->buf_len;
        for(i=0; i < (roundup(len, sizeof(u_int32_t))/4); i++) {
            *destp = le32_to_cpu(*srcp);
            destp++; srcp++;
        }
    }
#endif

    if (ev->buf_type == WMI_HOST_BUFFER_TYPE_RATEPWR_TABLE) {
        ol_if_ratepwr_recv_buf((u_int8_t *)(&ev->buf_info[0]), ev->buf_len,
                                ev->frag_id, ev->more_frag);
    } else if (ev->buf_type == WMI_HOST_BUFFER_TYPE_CTL_TABLE) {
        /* TODO */
    }
    return 0;
}

int ol_ath_peer_mumimo_tx_count_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_peer_txmu_cnt_event event, *ev = &event;

    if (wmi_extract_mumimo_tx_count_ev_param(scn->wmi_handle, data, ev)) {
        return -1;
    }
    qdf_print("MUMIMO tx for this peer %u\n",ev->tx_mu_transmitted);
    return 0;
}

int ol_ath_peer_gid_userpos_list_event_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
   wmi_host_peer_gid_userpos_list_event event, *ev = &event;

    if (wmi_extract_peer_gid_userpos_list_ev_param(scn->wmi_handle, data, ev)) {
        return -1;
    }
   qdf_print("User poistion list for GID 1->15:[%u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u]\n",
       ev->usr_list[0], ev->usr_list[1], ev->usr_list[2], ev->usr_list[3], ev->usr_list[4], ev->usr_list[5],
       ev->usr_list[6], ev->usr_list[7], ev->usr_list[8], ev->usr_list[9], ev->usr_list[10],ev->usr_list[11],
       ev->usr_list[12], ev->usr_list[13], ev->usr_list[14]);
   return 0;
}

int
ol_ath_mcast_list_ageout_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_mcast_list_ageout_event *ev;
    struct ieee80211vap *vap;
    int i;
    wmi_host_mcast_ageout_entry *temp_ptr;
    u_int8_t grp_addr[6]; /* mcast mac addr */
    u_int32_t grp_ipaddr; /* mcast ip addr */

    ev = (wmi_host_mcast_list_ageout_event*) data;

    if(ev){
        temp_ptr = ev->entry;
        grp_addr[0] = 0x01;
        grp_addr[1] = 0x00;
        grp_addr[2] = 0x5e;
        for(i=0; i< ev->num_entry; i++) {
            if( temp_ptr->grp_addr[0] != 0xff ){
                /* Not ipv6 mcast group address */
                /* Converting the multicast group ip address to multicast mac address */
                grp_addr[3] = temp_ptr->grp_addr[14] & 0x7f;
                grp_addr[4] = temp_ptr->grp_addr[13];
                grp_addr[5] = temp_ptr->grp_addr[12];
                grp_ipaddr  = temp_ptr->grp_addr[15] << 24 |
                              temp_ptr->grp_addr[14] << 16 |
                              temp_ptr->grp_addr[13] << 8  |
                              temp_ptr->grp_addr[12];
                vap = ol_ath_vap_get(scn, temp_ptr->vdev_id);
                if(vap){
                    if(vap->iv_ique_ops.me_deletegrp){
                        vap->iv_ique_ops.me_deletegrp( vap, grp_addr,
                                (u_int8_t*) &grp_ipaddr, ETHERTYPE_IP);
                    }
               }
            }
            temp_ptr++;
        }
    }
    return 0;
}

#if QCA_AIRTIME_FAIRNESS
int
ol_ath_atf_peer_stats_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_atf_peer_stats_event airtime;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ol_txrx_peer_t *peer;
    struct ieee80211_node *ni;
    uint32_t used, unused;
    uint32_t total, node_unusedtokens;
    wmi_host_atf_peer_stats_info token_info;
    int i, peer_id;

    total = 0;

    if(wmi_extract_atf_peer_stats_ev(scn->wmi_handle, data, &airtime)) {
	qdf_print("Unable to extract atf peer stats event\n");
	return -EINVAL;
    }

    for (i = 0; i < airtime.num_atf_peers; i++) {
	if (wmi_extract_atf_token_info_ev(scn->wmi_handle, data, i, &token_info)) {
	    qdf_print("Unable to extract atf token info\n");
	    return -EINVAL;
	}
        used = WMI_HOST_ATF_PEER_STATS_GET_USED_TOKENS(token_info) * 32;
        unused = WMI_HOST_ATF_PEER_STATS_GET_UNUSED_TOKENS(token_info) * 32;

        total += used + unused;
    }

    //printk("%s: recv atf peer evt. num %d max AT %d total %d\n", __func__, airtime->num_atf_peers, airtime->comp_usable_airtime, total);

    if(total < airtime.comp_usable_airtime)
        total = airtime.comp_usable_airtime;

    for (i = 0; i < airtime.num_atf_peers; i++) {
	if (wmi_extract_atf_token_info_ev(scn->wmi_handle, data, i, &token_info)) {
	    qdf_print("Unable to extract atf token info\n");
	    return -EINVAL;
	}
        used = WMI_HOST_ATF_PEER_STATS_GET_USED_TOKENS(token_info);
        unused = WMI_HOST_ATF_PEER_STATS_GET_UNUSED_TOKENS(token_info);
        peer_id = WMI_HOST_ATF_PEER_STATS_GET_PEER_AST_IDX(token_info);

        //printk("%d) ast idx 0x%x us 0x%x un 0x%x t 0x%x\n", i, peer_id, used, unused, used+unused);

        used = used * 32;
        unused = unused * 32;

        if (used+unused == 0)
            continue;

        peer = (peer_id == HTT_INVALID_PEER) ? NULL : scn->pdev_txrx_handle->peer_id_to_obj_map[peer_id];

        if (!peer) {
            //printk("peer id %d is NULL\n", peer_id);
            continue;
        }


        ni = ieee80211_find_node(&ic->ic_sta, peer->mac_addr.raw);
        if (!ni) {
            //printk("ni is NULL\n");
            continue;
        }

        ni->ni_atf_stats.act_tokens = used + unused;
        ni->ni_atf_stats.unused = node_unusedtokens = unused;
        ni->ni_atf_stats.total = total;

        if ( (ni->ni_atf_stats.act_tokens > node_unusedtokens) && (ni->ni_atf_stats.total > 0)) {
            // Note the math: 200k tokens every 200 ms => 1000k tokens / second => 1 token = 1 us.
            ni->ni_atf_stats.total_used_tokens += (ni->ni_atf_stats.act_tokens - node_unusedtokens);
            if (ic->ic_atf_logging) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "client %s is currently using %d usecs which is %d%% of available airtime\n",
                        ether_sprintf(ni->ni_macaddr),
                        (ni->ni_atf_stats.act_tokens - node_unusedtokens),
                        (((ni->ni_atf_stats.act_tokens - node_unusedtokens)*100) / ni->ni_atf_stats.total) );
            }
        }

        ieee80211_free_node(ni);
    }

    return 0;
}

int
ol_ath_tx_data_traffic_ctrl_event_handler (ol_scn_t scn, u_int8_t *data, u_int16_t datalen)
{
    wmi_host_tx_data_traffic_ctrl_event evt;
    struct ol_txrx_pdev_t *txrx_pdev    = scn->pdev_txrx_handle;
    struct ieee80211vap *vap;
    struct ieee80211_node *ni           = NULL;
    struct ol_txrx_peer_t *peer         = NULL;

	if(wmi_extract_tx_data_traffic_ctrl_ev(scn->wmi_handle, data, &evt)) {
	  qdf_print("Unable to extract tx data traffic\n");
	  return -EINVAL;
	}
	vap = ol_ath_vap_get(scn, evt.vdev_id);
    if(evt.peer_ast_idx == WMI_HOST_INVALID_PEER_AST_INDEX) {
        /* Invalid peer_ast_idx. Stop data tx traffic for a particular vap/vdev*/
        if (vap) {
            switch (evt.ctrl_cmd) {
                case WMI_HOST_TX_DATA_TRAFFIC_CTRL_UNBLOCK:
                    vap->iv_block_tx_traffic = 0; //allow traffic
                    break;
                case WMI_HOST_TX_DATA_TRAFFIC_CTRL_BLOCK:
                    vap->iv_block_tx_traffic = 1; //stop traffic
                    break;
                default:
                    break;
            }
        } else
               QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Could not find vap\n");
    } else {
        /* Stop data tx traffic for a particular node/peer */

        peer = txrx_pdev->peer_id_to_obj_map[evt.peer_ast_idx];
        if(peer) {
            if(vap) {
                ni = ieee80211_vap_find_node(vap, peer->mac_addr.raw);
                if(ni) {
                     switch (evt.ctrl_cmd) {
                         case WMI_HOST_TX_DATA_TRAFFIC_CTRL_UNBLOCK:
                             if(ni->ni_block_tx_traffic) {
                                 ni->ni_block_tx_traffic = 0; //allow traffic
                                 if(vap->tx_blk_cnt)
                                     vap->tx_blk_cnt--;
                             }
                             break;
                         case WMI_HOST_TX_DATA_TRAFFIC_CTRL_BLOCK:
                             if(!ni->ni_block_tx_traffic) {
                                 ni->ni_block_tx_traffic = 1; //stop traffic
                                 vap->tx_blk_cnt++;
                             }
                             break;
                         default:
                             break;
                     }
                    ieee80211_free_node(ni);
                } else
                    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Could not find node\n");
            } else
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Could not find vap\n");
        } else
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Could not find peer\n");
    }

    return 0;
}
#endif

u_int8_t ol_scn_vow_extstats(ol_pdev_handle pdev)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    return scn->vow_extstats;
}

u_int32_t ol_scn_vow_get_rxstats(ol_pdev_handle pdev, u_int32_t *phy_err_count, u_int32_t *rx_clear_count, u_int32_t *rx_cycle_count)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)pdev;
    *phy_err_count = scn->chan_stats.phy_err_cnt;
    *rx_clear_count = scn->mib_cycle_cnts.rx_clear_count;
    *rx_cycle_count = scn->mib_cycle_cnts.cycle_count;
    return 0;
}

#if OL_ATH_SUPPORT_LED
static OS_TIMER_FUNC(ol_ath_led_poll_timed_out)
{
    struct ol_ath_softc_net80211 *scn ;
    OS_GET_TIMER_ARG(scn, struct ol_ath_softc_net80211 *);

    if (!scn->scn_led_blink_rate_table) {
        return;
    }

    if (scn->scn_blinking != OL_BLINK_DONE)        /* don't interrupt active blink */
        return;

    ol_ath_led_event(scn, OL_ATH_LED_POLL);
}

static OS_TIMER_FUNC(ol_ath_led_blink_timed_out)
{
    struct ol_ath_softc_net80211 *scn ;
    OS_GET_TIMER_ARG(scn, struct ol_ath_softc_net80211 *);

    if (!scn->scn_led_blink_rate_table) {
        return;
    }

    switch (scn->scn_blinking) {
    case OL_BLINK_ON_START:
            scn->scn_blinking = OL_BLINK_DONE;
#if OL_ATH_SUPPORT_LED_POLL
            OS_SET_TIMER(&scn->scn_led_poll_timer, 500);
#endif
        break;
    case OL_BLINK_OFF_START:
            if(scn->target_type == TARGET_TYPE_IPQ4019) {
                ipq4019_wifi_led(scn, LED_OFF);
            } else {
                ol_ath_gpio_output(scn, scn->scn_led_gpio, 0);
            }
            scn->scn_blinking = OL_BLINK_ON_START;
            OS_SET_TIMER(&scn->scn_led_blink_timer, scn->scn_led_time_on);
        break;
    case OL_BLINK_STOP:
            if(scn->target_type == TARGET_TYPE_IPQ4019) {
                ipq4019_wifi_led(scn, LED_ON);
            } else {
                ol_ath_gpio_output(scn, scn->scn_led_gpio, 1);
            }
            scn->scn_blinking = OL_BLINK_DONE;
        break;
    case OL_BLINK_DONE:
    default:
        break;
    }
}

/*
 * Blink the LED according to the specified on/off times.
 */
static void
ol_ath_led_blink(struct ol_ath_softc_net80211 *scn, u_int32_t on, u_int32_t off)
{
    if(scn->target_type == TARGET_TYPE_IPQ4019) {
        ipq4019_wifi_led(scn, LED_ON);
    } else {
        ol_ath_gpio_output(scn, scn->scn_led_gpio, 1);
    }
    scn->scn_blinking = OL_BLINK_OFF_START;
    scn->scn_led_time_on = on;
    OS_SET_TIMER(&scn->scn_led_blink_timer, off);
}

void
ol_ath_led_event(struct ol_ath_softc_net80211 *scn, OL_LED_EVENT event)
{
    u_int32_t led_last_time = CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    u_int32_t map_idx;

    if (!scn || !(scn->scn_led_blink_rate_table)) {
        return;
    }

#if QCA_LTEU_SUPPORT
    if (scn->lteu_support)
        return;
#endif

    if (scn->scn_blinking != OL_BLINK_DONE)        /* don't interrupt active blink */
        return;
    switch (event) {
    case OL_ATH_LED_TX:
    case OL_ATH_LED_RX:
            /* 1/6554 = 1000 (ms -> sec) * 8 (Byte -> Bits) / 1024 *1024 ( -> Mega) * 50 (50 Mbps per entry) */
            map_idx = scn->scn_led_byte_cnt / ((led_last_time - scn->scn_led_last_time) * 6554);
            scn->scn_led_last_time = led_last_time;
            scn->scn_led_byte_cnt = 0;
            if (map_idx < 0) {
                map_idx = 0;
            } else if (map_idx > scn->scn_led_max_blink_rate_idx) {
                map_idx = scn->scn_led_max_blink_rate_idx;
            }
            ol_ath_led_blink(scn, scn->scn_led_blink_rate_table[map_idx].timeOn, scn->scn_led_blink_rate_table[map_idx].timeOff);
        break;
    case OL_ATH_LED_POLL:
            ol_ath_led_blink(scn, 100, 500);
        break;
    default:
        break;
    }
}
#endif /* OL_ATH_SUPPORT_LED */

#ifndef REMOVE_INIT_DEBUG_CODE
void ol_ath_dump_u32_buf(uint32_t *ptr, int len)
{
    int i;
#define WMI_MAX_DUMP_LEN 200
    len = len/4;
    len = (len > WMI_MAX_DUMP_LEN)?WMI_MAX_DUMP_LEN:len;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Dumping %p - %d words \n", ptr, len);
    /* Dump only initial part of pkt */
    for(i=0;i<len;i++) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%x ",*(ptr + i));
        if (i && (i % 8 == 0))
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");
    }
    wmi_init_flag = 0;
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");

}
#endif

uint32_t
ol_get_phymode_info(uint32_t chan_mode) {
    static const uint32_t modeflags[] = {
        0,                            /* IEEE80211_MODE_AUTO           */
        WMI_HOST_MODE_11A,         /* IEEE80211_MODE_11A            */
        WMI_HOST_MODE_11B,         /* IEEE80211_MODE_11B            */
        WMI_HOST_MODE_11G,         /* IEEE80211_MODE_11G            */
        0,                            /* IEEE80211_MODE_FH             */
        0,                            /* IEEE80211_MODE_TURBO_A        */
        0,                            /* IEEE80211_MODE_TURBO_G        */
        WMI_HOST_MODE_11NA_HT20,   /* IEEE80211_MODE_11NA_HT20      */
        WMI_HOST_MODE_11NG_HT20,   /* IEEE80211_MODE_11NG_HT20      */
        WMI_HOST_MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40PLUS  */
        WMI_HOST_MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40MINUS */
        WMI_HOST_MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40PLUS  */
        WMI_HOST_MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40MINUS */
        WMI_HOST_MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40      */
        WMI_HOST_MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40      */
        WMI_HOST_MODE_11AC_VHT20,  /* IEEE80211_MODE_11AC_VHT20     */
        WMI_HOST_MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40PLUS */
        WMI_HOST_MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40MINUS*/
        WMI_HOST_MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40     */
        WMI_HOST_MODE_11AC_VHT80,  /* IEEE80211_MODE_11AC_VHT80     */
        WMI_HOST_MODE_11AC_VHT160, /* IEEE80211_MODE_11AC_VHT160    */
        WMI_HOST_MODE_11AC_VHT80_80,/* IEEE80211_MODE_11AC_VHT160   */
    };
    /* Assert if the chan mode is invalid */
    qdf_assert_always(chan_mode < IEEE80211_MODE_MAX);
    return modeflags[chan_mode];
}

int ol_ath_set_tx_capture (struct ol_ath_softc_net80211 *scn, int val) {
    u_int32_t tx_capture;
    struct ol_txrx_pdev_t *pdev = NULL;

    pdev = scn->pdev_txrx_handle;
    tx_capture = scn->pl_dev->pl_info->tx_capture_enabled;
    if ((val == 1) && ((!scn->pl_dev->tgt_pktlog_enabled) && (!tx_capture))) {
        if (scn->pl_dev->pl_funcs->pktlog_enable(scn, ATH_PKTLOG_TX_CAPTURE_ENABLE) == 0) {
            qdf_print("\nEnabled Tx Capture\n");
            scn->pl_dev->pl_info->tx_capture_enabled = 1;
            pdev->tx_capture = 1;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_nss_ol_wifi_tx_capture_set(pdev, pdev->tx_capture);
#endif
            return 0;
        }
    } else if ((val == 0) && (tx_capture)) {
        if (scn->pl_dev->pl_funcs->pktlog_enable(scn, 0) == 0) {
            qdf_print("\nDisabled Tx Capture\n");
            scn->pl_dev->pl_info->tx_capture_enabled = 0;
            pdev->tx_capture = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_nss_ol_wifi_tx_capture_set(pdev, pdev->tx_capture);
#endif
            return 0;
        }
    }
    return -1;
}

#if OL_ATH_SMART_LOGGING
/*
 * API to enable/disable the smartlogging feature, if enabled
 * all fw logs, smartlog events are stored in smart_log_file
 */
int32_t
ol_ath_enable_smart_log(struct ol_ath_softc_net80211 *scn, uint32_t cfg)
{
    struct ieee80211com *ic = &(scn->sc_ic);

    if (cfg == 1) {
        if (ic->smart_logging == 1) {
            qdf_print("\nAlready Enabled\n");
        }
        else {
            if (smart_log_init(scn) == 0) {
                wmi_unified_send_smart_logging_enable_cmd(scn->wmi_handle, cfg);
            }
        }
    }
    else if (cfg == 0) {
        if (ic->smart_logging == 0) {
            qdf_print("\nAlready Disabled\n");
        }
        else {
            wmi_unified_send_smart_logging_enable_cmd(scn->wmi_handle, cfg);
            smart_log_deinit(scn);
        }
    }

    return 0;
}

/*
 * This api is used to send Smartlog event to the FW.
 * It is used when a fatal condition is detected in the host.
 * Once it is sent the FW reseponds by sending required logs
 * to host and sends a FATAL_COMPLETION_EVENT once its done
 * NOTE: Currently only @type is supported, subtype is always 0
 */
int32_t send_fatal_cmd(struct ol_ath_softc_net80211 *scn, uint32_t cfg)
{
    struct wmi_debug_fatal_events_t fevent;

    fevent.num_events = 1;
    fevent.event[0].type = cfg;
    fevent.event[0].subtype = 0;
    fevent.event[0].reserved0 = 0;

    return wmi_unified_send_smart_logging_fatal_cmd(scn->wmi_handle, &fevent);
}
#endif /* OL_ATH_SMART_LOGGING */

#if OL_ATH_CE_DEBUG
void
CE_debug_desc_trace_enable(struct ol_ath_softc_net80211 *scn, uint32_t cfg)
{
    struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)(scn->hif_hdl);
    hif_enable_desc_trace(hif_hdl, cfg);

    return;
}

uint32_t
CE_debug_desc_trace_enable_get(struct ol_ath_softc_net80211 *scn) {

    struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)(scn->hif_hdl);
    return hif_get_desc_trace_enabled(hif_hdl);
}
#endif /* OL_ATH_CE_DEBUG */
#endif

