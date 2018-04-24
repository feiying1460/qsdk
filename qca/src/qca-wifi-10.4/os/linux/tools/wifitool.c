/*
 * Copyright (c) 2013-2015, 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc
 */
/*
 * Copyright (c) 2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2010 Atheros Communications, Inc.

 * All rights reserved.
 */
/*
 * 2013-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * Notifications and licenses are retained for attribution purposes only.
 */

/*
 * athdbg athX cmd args
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <glob.h>           /* Including glob.h for glob() function used in find_pid() */
#include <signal.h>
#include <err.h>
#include <errno.h>
#if QCA_LTEU_SUPPORT
#include <pthread.h>
#include <unistd.h>
#define MAX_NUM_TRIES 5
#endif
/*
 * Linux uses __BIG_ENDIAN and __LITTLE_ENDIAN while BSD uses _foo
 * and an explicit _BYTE_ORDER.  Sorry, BSD got there first--define
 * things in the BSD way...
 */
#ifndef _LITTLE_ENDIAN
#define	_LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#endif
#ifndef _BIG_ENDIAN
#define	_BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */
#endif
#include <asm/byteorder.h>
#if defined(__LITTLE_ENDIAN)
#define	_BYTE_ORDER	_LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define	_BYTE_ORDER	_BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

/*
** Need to find proper references in UMAC code
*/

#include "os/linux/include/ieee80211_external.h"

#define	streq(a,b)	((strlen(a) == strlen(b)) && (strncasecmp(a,b,sizeof(b)-1) == 0))
#ifndef MAX_FIPS_BUFFER_SIZE
#define MAX_FIPS_BUFFER_SIZE (sizeof(struct ath_fips_output) + 1500)
#endif

static int tspectotime(struct timespec *tspec, struct tm *tmval, char *buffer, size_t len) {
    tzset();
    if (localtime_r(&(tspec->tv_sec), tmval) == NULL)
        return -1;

    strftime(buffer, len,"%Y-%m-%d %H:%M:%S %Z", tmval);
    return 0;
}

static void
usage(void)
{
    fprintf(stderr, "usage: wifitool athX cmd args\n");
    fprintf(stderr, "cmd: fips\t args: interface_name input_file\n"
                    "\tInput file format: Each set of inputs seperated by newline\n"
                    "\t<FIPS Command> <MODE> <Key length> <Input Data Length> <Key> <Input Data> <Expected Output> <IV with 16 bytes><newline>"
                    "\tExample: wifitool ath0 fips input_file \n Refer README_FIPS in drivers/wlan_modules/os/linux/tools\n");
    fprintf(stderr, "cmd: [sendaddba senddelba setaddbaresp getaddbastats  sendaddts senddelts  \n");
    fprintf(stderr, "cmd: [sendtsmrpt sendneigrpt sendlmreq sendbstmreq  sendbcnrpt ] \n");
    fprintf(stderr, "cmd: [sendstastats sendchload sendnhist sendlcireq rrmstats bcnrpt setchanlist getchanlist] \n");
    fprintf(stderr, "cmd: [block_acs_channel] \n");
    fprintf(stderr, "cmd: [rrm_sta_list] \n");
    fprintf(stderr, "cmd: [mu_scan lteu_cfg ap_scan] \n");
    fprintf(stderr, "cmd: [atf_debug_size atf_dump_debug] \n");
    fprintf(stderr, "cmd: [atf_debug_nodestate] \n");
    fprintf(stderr, "cmd: [tr069_get_vap_stats] \n");
    fprintf(stderr, "cmd: [tr069_chanhist] \n");
    fprintf(stderr, "cmd: [tr069_chan_inuse] \n");
    fprintf(stderr, "cmd: [tr069_set_oper_rate] \n");
    fprintf(stderr, "cmd: [tr069_get_oper_rate] \n");
    fprintf(stderr, "cmd: [tr069_get_posiblrate] \n");
    fprintf(stderr, "cmd: [chmask_persta] \n");
    fprintf(stderr, "cmd: [beeliner_fw_test] \n");
    fprintf(stderr, "cmd: [init_rtt3]\n");
    fprintf(stderr, "cmd: [bsteer_getparams bsteer_setparams] \n");
    fprintf(stderr, "cmd: [bsteer_getdbgparams bsteer_setdbgparams] \n");
    fprintf(stderr, "cmd: [bsteer_enable] [bsteer_enable_events] \n");
    fprintf(stderr, "cmd: [bsteer_getoverload bsteer_setoverload] \n");
    fprintf(stderr, "cmd: [bsteer_getrssi] \n");
    fprintf(stderr, "cmd: [bsteer_setproberespwh bsteer_getproberespwh] \n");
    fprintf(stderr, "cmd: [bsteer_setauthallow] \n");
    fprintf(stderr, "cmd: [set_antenna_switch] \n");
    fprintf(stderr, "cmd: [set_usr_ctrl_tbl] \n");
    fprintf(stderr, "cmd: [offchan_tx_test] \n");
    fprintf(stderr, "cmd: [sendbstmreq sendbstmreq_target] \n");
    fprintf(stderr, "cmd: [getrssi] \n");
    fprintf(stderr, "cmd: [bsteer_getdatarateinfo] \n");
    fprintf(stderr, "cmd: [tr069_get_fail_retrans] \n");
    fprintf(stderr, "cmd: [tr069_get_success_retrans] \n");
    fprintf(stderr, "cmd: [tr069_get_success_mul_retrans] \n");
    fprintf(stderr, "cmd: [tr069_get_ack_failures] \n");
    fprintf(stderr, "cmd: [tr069_get_retrans] \n");
    fprintf(stderr, "cmd: [tr069_get_aggr_pkts] \n");
    fprintf(stderr, "cmd: [tr069_get_sta_stats] [STA MAC] \n");
    fprintf(stderr, "cmd: [tr069_get_sta_bytes_sent] [STA MAC] \n");
    fprintf(stderr, "cmd: [tr069_get_sta_bytes_rcvd] [STA MAC] \n");
    fprintf(stderr, "cmd: [bsteer_setsteering] \n");
    fprintf(stderr, "cmd: [custom_chan_list] \n");
#if UMAC_SUPPORT_VI_DBG    
    fprintf(stderr, "cmd: [vow_debug_set_param] \n");
    fprintf(stderr, "cmd: [vow_debug] \n");
#endif    
	exit(-1);
}

static void
usage_setchanlist(void)
{
 	fprintf(stderr, "usage: wifitool athX setchanlist ch1 ch2 .....n \n");
}
static void
usage_set_usr_ctrl_tbl(void)
{
 	fprintf(stderr, "usage: wifitool athX set_usr_ctrl_tbl val1 val2 .....n \n");
        exit(-1);
}

static void
usage_offchan_tx_test(void)
{
 	fprintf(stderr, "usage: wifitool athX offchan_tx_test chan dwell_time \n");
        exit(-1);
}

static void
usage_getchanlist(void)
{
 	fprintf(stderr, "usage: wifitool athX getchanlist \n");
}
static void
usage_getrrrmstats(void)
{
   fprintf(stderr, "usage: wifitool athX get_rrmstats  [dstmac]\n");
   fprintf(stderr, "[dstmac] - stats reported by the given station\n");
}
static void
usage_getrssi(void)
{
 	fprintf(stderr, "usage: wifitool athX get_rssi  [dstmac]\n");
	fprintf(stderr, "[dstmac] - stats reported by the given station\n");
}
static void
usage_acsreport(void)
{
 	fprintf(stderr, "usage: wifitool athX acsreport\n");
}
static void usage_sendfrmreq(void)
{
   fprintf(stderr, "usage: wifitool athX sendfrmreq  <dstmac> <n_rpts> <reg_class> <chnum> \n");
   fprintf(stderr, "<rand_invl> <mandatory_duration> <req_type> <ref mac> \n");
   exit(-1);
}

static void
usage_sendlcireq(void)
{
   fprintf(stderr, "usage: wifitool athX sendlcireq  <dstmac> <location> <latitude_res> <longitude_res> \n");
   fprintf(stderr, "<altitude_res> [azimuth_res] [azimuth_type]\n");
   fprintf(stderr, "<dstmac> - MAC address of the receiving station \n");
   fprintf(stderr, "<location> - location of requesting/reporting station \n");
   fprintf(stderr, "<latitude_res> - Number of most significant bits(max 34) for fixed-point value of latitude \n");
   fprintf(stderr, "<longitude_res> - Number of most significant bits(max 34) for fixed-point value of longitude\n");
   fprintf(stderr, "<altitude_res> - Number of most significant bits(max 30) for fixed-point value of altitude\n");
   fprintf(stderr, "<azimuth_res> -  Number of most significant bits(max 9) for fixed-point value of Azimuth\n");
   fprintf(stderr, "<azimuth_type> - specifies report of azimuth of radio reception(0) or front surface(1) of reporting station\n");
   exit(-1);
}

static void
usage_sendchloadrpt(void)
{
   fprintf(stderr, "usage: wifitool athX sendchload  <dstmac> <n_rpts> <reg_class> <chnum> \n");
   fprintf(stderr, "<rand_invl> <mandatory_duration> <optional_condtion> <condition_val>\n");
   exit(-1);
}

static void
usage_sendnhist(void)
{
   fprintf(stderr, "usage: wifitool athX sendnhist  <dstmac> <n_rpts> <reg_class> <chnum> \n");
   fprintf(stderr, "<rand_invl> <mandator_duration> <optional_condtion> <condition_val>\n");
   exit(-1);
}

static void
usage_sendstastatsrpt(void)
{
   fprintf(stderr, "usage: wifitool athX sendstastats  <dstmac> <duration> <gid>\n");
   exit(-1);
}

static void
usage_rrmstalist(void)
{
    fprintf(stderr, "usage: wifitool athX rrm_sta_list \n");
    exit(-1);
}

static void
usage_sendaddba(void)
{
   fprintf(stderr, "usage: wifitool athX sendaddba <aid> <tid> <buffersize>\n");
   exit(-1);
}


static void
usage_senddelba(void)
{
   fprintf(stderr, "usage: wifitool athX senddelba <aid> <tid> <initiator> <reasoncode> \n");
   exit(-1);
}

static void
usage_setaddbaresp(void)
{
   fprintf(stderr, "usage: wifitool athX setaddbaresp <aid> <tid> <statuscode> \n");
   exit(-1);
}

static void
usage_sendsingleamsdu(void)
{
   fprintf(stderr, "usage: wifitool athX sendsingleamsdu <aid> <tid> \n");
   exit(-1);
}

static void
usage_beeliner_fw_test(void)
{
   fprintf(stderr, "usage: wifitool athX beeliner_fw_test <arg> <value> \n");
   exit(-1);
}
static void
usage_init_rtt3(void)
{
    fprintf(stderr, "usage: wifitool athX init_rtt3 <dstmac> <extra> ");
    exit(-1);
}
static void
usage_getaddbastats(void)
{
   fprintf(stderr, "usage: wifitool athX setaddbaresp <aid> <tid> \n");
   exit(-1);
}

static void
usage_sendbcnrpt(void)
{
   fprintf(stderr, "usage: wifitool athX sendbcnrpt <dstmac> <regclass> <channum> \n");
   fprintf(stderr, "       <rand_ivl> <duration> <mode> \n");
   fprintf(stderr, "       <req_ssid> <rep_cond> <rpt_detail>\n");
   fprintf(stderr, "       <req_ie> <chanrpt_mode> [specific_bssid]\n");
   fprintf(stderr, "       req_ssid = 1 for ssid, 2 for wildcard ssid \n");
   exit(-1);
}

static void
usage_chmask_persta(void)
{
    fprintf(stderr, "usage: wifitool athX chmask_persta <mac_addr> <nss> \n");
    exit(-1);
}

static void
usage_set_antenna_switch(void)
{
   fprintf(stderr, "usage: wifitool athX set_antenna_switch <ctrl_cmd_1> <ctrl_cmd_2> \n");
   exit(-1);
}

static void
usage_sendtsmrpt(void)
{
   fprintf(stderr, "usage: wifitool athX sendtsmrpt <num_rpt> <rand_ivl> <meas_dur>\n");
   fprintf(stderr, "       <tid> <macaddr> <bin0-range> <trig_cond> \n");
   fprintf(stderr, "       <avg_err_thresh> <cons_err_thresh> <delay_thresh> <trig_timeout>\n");
   exit(-1);
}

static void
usage_sendneigrpt(void)
{
   fprintf(stderr, "usage: wifitool athX sendneigrpt <mac_addr> <ssid> <dialog_token>  \n");
   exit(-1);
}

static void
usage_sendlmreq(void)
{
   fprintf(stderr, "usage: wifitool athX sendlmreq <mac_addr> \n");
   exit(-1);
}

static void
usage_setbssidpref(void)
{
    fprintf(stderr, "usage: wifitool athX setbssidpref <mac_addr> <pref_val> <operating class> <channel number> \n");
    exit(-1);
}

static void
usage_sendbstmreq(void)
{
   fprintf(stderr, "usage: wifitool athX sendbstmreq <mac_addr> <candidate_list> <disassoc_timer> <validityItrv> [disassoc_imminent][bss_term_inc] \n");
   exit(-1);
}

static void
usage_sendbstmreq_target(void)
{
   fprintf(stderr, "usage: wifitool athX sendbstmreq_target <mac_addr>\n[<candidate_bssid> <candidate channel> <candidate_preference> <operating class> <PHY type>...]\n");
   exit(-1);
}

static void
usage_senddelts(void)
{
   fprintf(stderr, "usage: wifitool athX senddelts <mac_addr> <tid> \n");
   exit(-1);
}

static void
usage_sendaddts(void)
{
   fprintf(stderr, "usage: wifitool athX sendaddts <mac_addr> <tid> <dir> <up>\
           <nominal_msdu> <mean_data_rate> <mean_phy_rate> <surplus_bw>\
                             <uapsd-bit> <ack_policy> <max_burst_size>\n");
   exit(-1);
}

static void
usage_tr069chanhist(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_chanhist\n");
}
static void
usage_tr069_txpower(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_txpower Power(in percentage)\n");
}
static void
usage_tr069_gettxpower(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_gettxpower \n");
}
static void
usage_tr069_guardintv(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_guardintv time(in nanoseconds) (800 or 0 for auto)\n");
}
    static void
usage_tr069_get_guardintv(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_get_guardintv \n");
}
    static void
usage_tr069_getassocsta(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_getassocsta \n");
}
    static void
usage_tr069_gettimestamp(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_gettimestamp \n");
}
    static void
usage_tr069_getacsscan(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_getacsscan (1 to issue a scan and 0 to know the result of scan) \n");
}
    static void
usage_tr069_perstastatscount(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_persta_statscount \n");
}
    static void
usage_tr069_get11hsupported(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_get_11hsupported \n");
}
    static void
usage_tr069_getpowerrange(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_get_powerrange \n");
}

    static void
usage_tr069_chan_inuse(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_chan_inuse\n");
}

    static void
usage_tr069_setoprate(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_setoprate rate1,rate2, .....n \n");
}

    static void
usage_tr069_getoprate(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_getoprate \n");
}

    static void
usage_tr069_getposrate(void)
{
    fprintf(stderr, "usage: wifitool athX tr069_getposrate \n");
}

static void
usage_tr069_getsupportedfrequency(void)
{
    fprintf(stderr, "usage: wifitool athX supported_freq \n");
}
static void
usage_assoc_dev_watermark_time(void)
{
   fprintf(stderr, "usage: wifitool athX get_assoc_dev_watermark_time \n");
}
static void
usage_bsteer_getparams(void)
{
    fprintf(stderr, "usage: wifitool athX bsteer_getparams \n");
}
static void
usage_bsteer_setparams(void)
{
    fprintf(stderr, "usage: wifitool athX bsteer_setparams <inact_normal> <inact_overload> <util_sample_period>\n"
                    "           <util_average_num_samples> <inactive_rssi_xing_high_threshold> <inactive_rssi_xing_low_threshold>\n"
                    "           <low_rssi_crossing_threshold> <inact_check_period> <tx_rate_low_crossing_threshold>\n"
                    "           <tx_rate_high_crossing_threshold> <rssi_rate_low_crossing_threshold> <rssi_rate_high_crossing_threshold>\n"
                    "           <ap_steer_rssi_low_threshold> <interference_detection_enable>\n");
}

static void
usage_bsteer_getdbgparams(void)
{
    fprintf(stderr, "usage: wifitool athX bsteer_getdbgparams \n");
}

static void
usage_bsteer_setdbgparams(void)
{
    fprintf(stderr, "usage: wifitool athX bsteer_setdbgparams "
                    "<raw_chan_util_log_enable> "
                    "<raw_rssi_log_enable> <raw_tx_rate_log_enable>\n");
}

static void
usage_bsteer_enable(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_enable <enable_flag>\n");
}

static void
usage_bsteer_enable_events(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_enable_events <enable_flag>\n");
}

static void
usage_bsteer_setoverload(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_setoverload <overload_flag>\n");
}

static void
usage_bsteer_getoverload(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_getoverload\n");
}

static void
usage_bsteer_getrssi(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_getrssi <dstmac> <num_samples>\n");
}

static void
usage_bsteer_setproberespwh(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_setproberespwh <dstmac> <enable_flag>\n");
}

static void
usage_bsteer_getproberespwh(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_getproberespwh <dstmac>\n");
}

static void
usage_bsteer_setauthallow(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_setauthallow <dstmac> <enable_flag>\n");
}

static void
usage_bsteer_getdatarateinfo(void)
{
    fprintf(stderr, "Usage: wifitool athX bsteer_getdatarateinfo <dstmac>\n");
}

static void
usage_bsteer_setsteering(void)
{
    fprintf(stderr, "Usage, wifitool athX bsteer_setsteering <dstmac> <steering_flag>\n");
}

static void
usage_set_innetwork_2g(void)
{
   fprintf(stderr, "usage: wifitool athX set_innetwork_2g [mac] channel\n");
}

static void
usage_get_innetwork_2g(void)
{
   fprintf(stderr, "usage: wifitool athX get_innetwork_2g\n");
}


#if UMAC_SUPPORT_VI_DBG
static void
usage_vow_debug(void)
{
	    fprintf(stderr, "Usage, wifitool athX vow_debug <stream_num> <marker_num> <marker_offset> <marker_match>\n");
}

static void
usage_vow_debug_set_param(void)
{
	fprintf(stderr, "Usage, wifitool athX vow_debug_set_param <num_stream> <num_marker> <rxseqnum> <rxseqshift> <rxseqmax> <time_offset>\n");
}
#endif

static void
usage_display_traffic_statistics(void)
{
    fprintf(stderr, "usage: wifitool athX display_traffic_statistics \n");
}
/*
 * Input an arbitrary length MAC address and convert to binary.
 * Return address size.
 */
typedef unsigned char uint8_t;

uint8_t delim_unix = ':';
uint8_t delim_win = '-';

#define IS_VALID(s)         (((s >= '0') && (s <= '9')) || ((s >= 'A') && (s <= 'F')) || ((s >= 'a') && (s <= 'f')))
#define TO_UPPER(s)         (((s >= 'a') && (s <= 'z')) ? (s - 32) : s)
#define IS_NUM(c)           ((c >= '0') && (c <= '9'))
#define CHAR_TO_HEX_INT(c)  (IS_NUM(c) ? (c - '0') : (TO_UPPER(c) - 55))

/* returns 0 for fail else len if success */

int
wifitool_mac_aton(const char *str,
        unsigned char *     out,
        int                 len)
{
    int index = 0;
    const uint8_t *tmp = NULL;
    int plen = 0;
    uint8_t delim;
    int num = 0;
    int flag_num_valid = 0;
    int ccnt = 0;

    while((*str == ' ') || (*str == '\t') || (*str == '\n')) {
        ++str;
    }

    tmp = (uint8_t *) str;

    while ((*tmp != delim_unix) && (*tmp != delim_win)) {
        ++tmp;
    }

    delim = *tmp;

    tmp = (uint8_t *)str;

    while (*tmp != '\0') {

        if (IS_VALID(*tmp) && (++ccnt < 3)) {
            num = (num * 16) + CHAR_TO_HEX_INT(*tmp);
            flag_num_valid = 1;
        } else if ((*tmp == delim) && (flag_num_valid)) {
            *out = num;
            out++;
            num = 0;
            plen++;
            ccnt = 0;
            flag_num_valid = 0;

            if (plen > len) {
                return 0;
            }
        } else {
            return 0;
        }
        tmp++;
    }

    if (*tmp == '\0') {
        *out = num;
        plen++;
    }

    if (plen == len) {
        return len;
    } else {
        return 0;
    }

}


static void
send_addba(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 6) {
        usage_sendaddba();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDADDBA;
        req.data.param[0] = atoi(argv[3]);
        req.data.param[1] = atoi(argv[4]);
        req.data.param[2] = atoi(argv[5]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to send addba");
        }
        close(s);
    }
    return;
}

    static void
send_delba(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 7) {
        usage_senddelba();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDDELBA;
        req.data.param[0] = atoi(argv[3]);
        req.data.param[1] = atoi(argv[4]);
        req.data.param[2] = atoi(argv[5]);
        req.data.param[3] = atoi(argv[6]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to send delba");
        }
        close(s);
    }
    return;
}

    static void
set_addbaresp(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 6) {
        usage_sendaddba();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SETADDBARESP;
        req.data.param[0] = atoi(argv[3]);
        req.data.param[1] = atoi(argv[4]);
        req.data.param[2] = atoi(argv[5]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to addba response");
        }
        close(s);
    }
    return;
}

static void
send_singleamsdu(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 5) {
        usage_sendsingleamsdu();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDSINGLEAMSDU;
        req.data.param[0] = atoi(argv[3]);
        req.data.param[1] = atoi(argv[4]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to send single AMSDU ");
        }
        close(s);
    }
    return;
}

static void
get_addbastats(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 5) {
        usage_getaddbastats();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_GETADDBASTATS;
        req.data.param[0] = atoi(argv[3]);
        req.data.param[1] = atoi(argv[4]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to get addba stats");
        }
        close(s);
    }
    return;
}

/**
 * @brief Parse the command and append AP channel report subelements
 *        to the beacon report.
 *
 * This is only valid for US Operating classes.
 *
 * @param [out] bcnrpt  the beacon report to be filled with AP channel
 *                      report subelements
 * @param [in] argc  total number of command line arguments
 * @param [in] argv  command line arguments
 * @param [in] offset  the start of channel number arguments
 *
 * @return -1 if any channel number provided is invalid; otherwise
 *         return 0 on success
 */
static int
bcnrpt_append_chan_report(ieee80211_rrm_beaconreq_info_t* bcnrpt,
                          int argc, char *argv[], int offset) {
    /* For now only consider Operating class 1,2,3,4 and 12,
       as defined in Table E-1 in 802.11-REVmb/D12, November 2011 */
#define MAX_CHANNUM_PER_REGCLASS 11
    typedef enum {
        REGCLASS_1 = 1,
        REGCLASS_2 = 2,
        REGCLASS_3 = 3,
        REGCLASS_4 = 4,
        REGCLASS_12 = 12,

        REGCLASS_MAX
    } regclass_e;

    int num_chanrep = 0;
    regclass_e regclassnum = REGCLASS_MAX;
    struct {
        int numchans;
        int channum[MAX_CHANNUM_PER_REGCLASS];
    } regclass[REGCLASS_MAX] = {{0}};

    while (offset < argc) {
        int channum = atoi(argv[offset++]);
        switch (channum) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
                regclassnum = REGCLASS_12;
                break;
            case 36:
            case 40:
            case 44:
            case 48:
                regclassnum = REGCLASS_1;
                break;
            case 52:
            case 56:
            case 60:
            case 64:
                regclassnum = REGCLASS_2;
                break;
            case 149:
            case 153:
            case 157:
            case 161:
                regclassnum = REGCLASS_3;
                break;
            case 100:
            case 104:
            case 108:
            case 112:
            case 116:
            case 120:
            case 124:
            case 128:
            case 132:
            case 136:
            case 140:
                regclassnum = REGCLASS_4;
                break;
            default:
                return -1;
        }

        if (regclass[regclassnum].numchans >= MAX_CHANNUM_PER_REGCLASS) {
            /* Must have duplicated entries, raise error to user */
            return -1;
        }

        regclass[regclassnum].channum[regclass[regclassnum].numchans] = channum;
        ++regclass[regclassnum].numchans;
    }

    for (regclassnum = REGCLASS_1; regclassnum < REGCLASS_MAX; regclassnum++) {
        if (regclass[regclassnum].numchans > 0) {
            /* Use global op class if specified in the bcnrpt */
            if ((bcnrpt->regclass == 81) || (bcnrpt->regclass == 115))
                bcnrpt->apchanrep[num_chanrep].regclass = bcnrpt->regclass;
            else
                bcnrpt->apchanrep[num_chanrep].regclass = regclassnum;

            bcnrpt->apchanrep[num_chanrep].numchans = regclass[regclassnum].numchans;
            int i;
            for (i = 0; i < regclass[regclassnum].numchans; i++) {
                bcnrpt->apchanrep[num_chanrep].channum[i] = regclass[regclassnum].channum[i];
            }
            if (++num_chanrep >= IEEE80211_RRM_NUM_CHANREP_MAX) {
                break;
            }
        }
    }

    bcnrpt->num_chanrep = num_chanrep;
    return 0;
}

static void
send_bcnrpt(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_beaconreq_info_t* bcnrpt = &req.data.bcnrpt;
    int chan_rptmode = 0;
    if (argc < 14) {
        usage_sendbcnrpt();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDBCNRPT;
        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        bcnrpt->regclass = atoi(argv[4]);
        bcnrpt->channum = atoi(argv[5]);
        bcnrpt->random_ivl = atoi(argv[6]);
        bcnrpt->duration = atoi(argv[7]);
        bcnrpt->mode = atoi(argv[8]);
        bcnrpt->req_ssid = atoi(argv[9]);
        bcnrpt->rep_cond = atoi(argv[10]);
        bcnrpt->rep_detail = atoi(argv[11]);
        bcnrpt->req_ie = atoi(argv[12]);
        chan_rptmode = atoi(argv[13]);
        if (argc < 15) {
            bcnrpt->bssid[0] = 0xff;
            bcnrpt->bssid[1] = 0xff;
            bcnrpt->bssid[2] = 0xff;
            bcnrpt->bssid[3] = 0xff;
            bcnrpt->bssid[4] = 0xff;
            bcnrpt->bssid[5] = 0xff;
        } else {
            if (!wifitool_mac_aton(argv[14], bcnrpt->bssid, 6)) {
                errx(1, "Invalid BSSID");
                return;
            }
        }
        if (!chan_rptmode) {
            bcnrpt->num_chanrep = 0;
        } else if (argc < 16) {
            /* If no channel is provided, use pre-canned channel values */
            if (bcnrpt->regclass == 81) {
                /* Global op class 81 */
                bcnrpt->num_chanrep = 1;
                bcnrpt->apchanrep[0].regclass = bcnrpt->regclass;
                bcnrpt->apchanrep[0].numchans = 2;
                bcnrpt->apchanrep[0].channum[0] = 1;
                bcnrpt->apchanrep[0].channum[1] = 6;
            } else if (bcnrpt->regclass == 115) {
                /* Global op class 115 */
                bcnrpt->num_chanrep = 1;
                bcnrpt->apchanrep[0].regclass = bcnrpt->regclass;
                bcnrpt->apchanrep[0].numchans = 2;
                bcnrpt->apchanrep[0].channum[0] = 36;
                bcnrpt->apchanrep[0].channum[1] = 48;
            } else {
                bcnrpt->num_chanrep = 2;
                bcnrpt->apchanrep[0].regclass = 12;
                bcnrpt->apchanrep[0].numchans = 2;
                bcnrpt->apchanrep[0].channum[0] = 1;
                bcnrpt->apchanrep[0].channum[1] = 6;
                bcnrpt->apchanrep[1].regclass = 1;
                bcnrpt->apchanrep[1].numchans = 2;
                bcnrpt->apchanrep[1].channum[0] = 36;
                bcnrpt->apchanrep[1].channum[1] = 48;
            }
        } else if (bcnrpt_append_chan_report(bcnrpt, argc, argv, 15) < 0) {
            errx(1, "Invalid AP Channel Report channel number(s)");
            usage_sendbcnrpt();
        }
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ failed");
        }
        close(s);
    }
    return;
}

static void
send_tsmrpt(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_tsmreq_info_t *tsmrpt = &req.data.tsmrpt;
    if (argc < 14) {
        usage_sendtsmrpt();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDTSMRPT;
        tsmrpt->num_rpt = atoi(argv[3]);
        tsmrpt->rand_ivl = atoi(argv[4]);
        tsmrpt->meas_dur = atoi(argv[5]);
        tsmrpt->tid = atoi(argv[6]);
        if (!wifitool_mac_aton(argv[7], tsmrpt->macaddr, 6)) {
            errx(1, "Invalid mac address");
            return;
        }
        tsmrpt->bin0_range = atoi(argv[8]);
        tsmrpt->trig_cond = atoi(argv[9]);
        tsmrpt->avg_err_thresh = atoi(argv[10]);
        tsmrpt->cons_err_thresh = atoi(argv[11]);
        tsmrpt->delay_thresh = atoi(argv[12]);
        tsmrpt->trig_timeout = atoi(argv[13]);
        memcpy(req.dstmac, tsmrpt->macaddr, 6);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDTSMRPT failed");
        }
        close(s);
    }
    return;
}

static void
send_neigrpt(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_nrreq_info_t *neigrpt = &req.data.neigrpt;
    if (argc < 5) {
        usage_sendneigrpt();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDNEIGRPT;
        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        memset((char *)neigrpt->ssid, '\0', sizeof(neigrpt->ssid));
        if (strlcpy((char *)neigrpt->ssid, argv[4], sizeof(neigrpt->ssid)) >= sizeof(neigrpt->ssid)) {
            errx(1, "Argument length too long %s", argv[4]);
        }

        neigrpt->ssid[sizeof(neigrpt->ssid)-1] = '\0';
        neigrpt->ssid_len = strlen((char *)neigrpt->ssid);
        neigrpt->dialogtoken = atoi(argv[5]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDNEIGRPT failed");
        }
        close(s);
    }
    return;
}

static void
send_lmreq(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 4) {
        usage_sendlmreq();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDLMREQ;
        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDLMREQ failed");
        }
        close(s);
    }
    return;
}

static void
set_bssidpref(const char *ifname,int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    struct ieee80211_user_bssid_pref* userpref = &req.data.bssidpref;
    if(argc < 7) {
        usage_setbssidpref();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_MBO_BSSIDPREF;

        if (strcmp( argv[3],"0") == 0)
            userpref->pref_val = 0;
        else {
            if (!wifitool_mac_aton(argv[3], userpref->bssid, 6)) {
                errx(1, "Invalid mac address entered");
                close(s);
                return;
            }
            userpref->pref_val =(u_int8_t)(atoi(argv[4]));
            userpref->regclass =(u_int8_t)(atoi(argv[5]));
            userpref->chan =(u_int8_t)(atoi(argv[6]));
        }

        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_MBO_BSSIDPREF failed");
        }
        close(s);
    }
    return;
}

static void
send_bstmreq(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    struct ieee80211_bstm_reqinfo* reqinfo = &req.data.bstmreq;
    if (argc < 7) {
        usage_sendbstmreq();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDBSTMREQ;
        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        reqinfo->dialogtoken = 1;
        reqinfo->candidate_list = atoi(argv[4]);
        reqinfo->disassoc_timer = atoi(argv[5]);
        reqinfo->validity_itvl = atoi(argv[6]);

        reqinfo->bssterm_inc = 0;
        reqinfo->disassoc = 0;
        reqinfo->bssterm_tsf = 0;
        reqinfo->bssterm_duration = 0;

        if (argc > 7) {
            reqinfo->disassoc = atoi(argv[7]);
        }
        if (argc > 8) {
            reqinfo->bssterm_inc = atoi(argv[8]);
        }
        if (argc > 9) {
            reqinfo->bssterm_tsf = atoi(argv[9]);
        }
        if (argc > 10) {
            reqinfo->bssterm_duration = atoi(argv[10]);
        }
        if (argc > 11) {
            reqinfo->abridged = atoi(argv[11]);
        }

        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDBSTMREQ failed");
        }
        close(s);
    }
    return;
}

static void
send_bstmreq_target(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len, i;
    struct ieee80211req_athdbg req;
    struct ieee80211_bstm_reqinfo_target* reqinfo = &req.data.bstmreq_target;

    /* constants for convenient checking of arguments */
    static const u_int32_t fixed_length_args = 4;
    static const u_int32_t per_candidate_args = 5;

    if (argc < fixed_length_args) {
        usage_sendbstmreq_target();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));

        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDBSTMREQ_TARGET;
        if (!wifitool_mac_aton(argv[3], req.dstmac, MAC_ADDR_LEN)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        reqinfo->dialogtoken = 1;

        /* check the number of arguments is appropriate to have the full complement
           of parameters for the command */
        if ((argc - fixed_length_args) % per_candidate_args) {
            usage_sendbstmreq_target();
            return;
        }

        reqinfo->num_candidates = (argc - fixed_length_args) / per_candidate_args;

        /* make sure the maximum number of candidates is not exceeded */
        if (reqinfo->num_candidates > ieee80211_bstm_req_max_candidates) {
            errx(1, "Invalid number of candidates: %d, maximum is %d",
                 reqinfo->num_candidates, ieee80211_bstm_req_max_candidates);
            return;
        }

        /* read the candidates */
        for (i = 0; i < reqinfo->num_candidates; i++) {
            if (!wifitool_mac_aton(argv[fixed_length_args + i * per_candidate_args],
                                   reqinfo->candidates[i].bssid, MAC_ADDR_LEN)) {
                errx(1, "Candidate entry %d: Invalid BSSID", i);
                return;
            }
            reqinfo->candidates[i].channel_number = atoi(argv[fixed_length_args + i * per_candidate_args + 1]);
            reqinfo->candidates[i].preference = atoi(argv[fixed_length_args + i * per_candidate_args + 2]);
            reqinfo->candidates[i].op_class = atoi(argv[fixed_length_args + i * per_candidate_args + 3]);
            reqinfo->candidates[i].phy_type = atoi(argv[fixed_length_args + i * per_candidate_args + 4]);
        }

        s = socket(AF_INET, SOCK_DGRAM, 0);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDBSTMREQ_TARGET failed");
        }

        close(s);
    }
    return;
}

static void
send_delts(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if (argc < 5) {
        usage_senddelts();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDDELTS;
        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        req.data.param[0] = atoi(argv[4]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to delts");
        }
        close(s);
    }
    return;
}

static void
send_addts(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_tspec_info* tsinfo = &req.data.tsinfo;
    if (argc < 13) {
        usage_sendaddts();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDADDTSREQ;
        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        tsinfo->tid = atoi(argv[4]);
        tsinfo->direction = atoi(argv[5]);
        tsinfo->dot1Dtag = atoi(argv[6]);
        tsinfo->norminal_msdu_size = atoi(argv[7]);
        tsinfo->mean_data_rate = atoi(argv[8]);
        tsinfo->min_phy_rate = atoi(argv[9]);
        tsinfo->surplus_bw = atoi(argv[10]);
        tsinfo->psb = atoi(argv[11]);
        tsinfo->ack_policy = atoi(argv[12]);
        tsinfo->max_burst_size = atoi(argv[13]);
        tsinfo->acc_policy_edca = 1;
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "unable to send ADDTS REQ");
        }
        close(s);
    }
    return;
}

static void
send_noisehistogram(const char *ifname, int argc, char *argv[])
{
    int s, len;
    struct iwreq iwr;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_nhist_info_t *nhist = &req.data.nhist;

    if ((argc < 9) || (argc > 11)) {
        usage_sendnhist();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDNHIST;
        if (!wifitool_mac_aton(argv[3], nhist->dstmac, 6)) {
            errx(1, "Invalid mac address");
            return;
        }
        nhist->num_rpts = atoi(argv[4]);
        nhist->regclass = atoi(argv[5]);
        nhist->chnum = atoi(argv[6]);
        nhist->r_invl = atoi(argv[7]);
        nhist->m_dur  = atoi(argv[8]);
        if(argc > 9 ) { /*optional element */
            nhist->cond  = atoi(argv[9]);
            nhist->c_val  = atoi(argv[10]);
        }
        memcpy(req.dstmac, nhist->dstmac, 6);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDNHISTT failed");
        }
        close(s);
    }
    return;
}
void print_rrmstats(FILE *fd,
                    ieee80211_rrmstats_t *rrmstats,int unicast)
{
    u_int32_t chnum=0, i;
    u_int8_t buf[80];
    ieee80211_rrm_noise_data_t  noise_invalid;
    ieee80211_rrm_noise_data_t  *noise_dptr;
    ieee80211_rrm_lci_data_t    *lci_info;
    ieee80211_rrm_statsgid0_t   *gid0;
    ieee80211_rrm_statsgid10_t  *gid10;
    ieee80211_rrm_statsgid1_t   *gid1;
    ieee80211_rrm_statsgidupx_t *gidupx;
    ieee80211_rrm_tsm_data_t    *tsmdata;
    ieee80211_rrm_lm_data_t     *lmdata;
    ieee80211_rrm_frmcnt_data_t *frmcnt;


    memset(&noise_invalid, 0x0, sizeof(ieee80211_rrm_noise_data_t));


    if(!unicast ) {
        fprintf(fd, "Channel# Chan_load \tANPI\t\tIPI[0 - 11]");
        for (chnum = 0; chnum < IEEE80211_RRM_CHAN_MAX;chnum++)
        {
            if (rrmstats->noise_data[chnum].anpi != 0 || rrmstats->chann_load[chnum] != 0)
            {
                fprintf(fd,"\n");
                fprintf(fd ,"%d\t ",chnum);
                fprintf(fd ,"%d \t\t",rrmstats->chann_load[chnum]);
                fprintf(fd, "%d\t\t ",rrmstats->noise_data[chnum].anpi);
                noise_dptr = &rrmstats->noise_data[chnum];
                for (i = 0; i < 11; i++)
                {
                    fprintf(fd, "%d, ", noise_dptr->ipi[i]);
                }
            }
        }
        fprintf(fd,"\n");
    }else {
        lci_info = &rrmstats->ni_rrm_stats.ni_vap_lciinfo;
        fprintf(fd, "\n");
        fprintf(fd, "LCI local information :\n");
        fprintf(fd, "--------------------\n");
        fprintf(fd, "\t\t latitude %d.%d longitude %d.%d Altitude %d.%d\n", lci_info->lat_integ,
                lci_info->lat_frac, lci_info->alt_integ, lci_info->alt_frac,
                lci_info->alt_integ, lci_info->alt_frac);
        lci_info = &rrmstats->ni_rrm_stats.ni_rrm_lciinfo;
        fprintf(fd, "\n");
        fprintf(fd, "LCI local information :\n");
        fprintf(fd, "--------------------\n");
        fprintf(fd, "\t\t latitude %d.%d longitude %d.%d Altitude %d.%d\n", lci_info->lat_integ,
                lci_info->lat_frac, lci_info->alt_integ, lci_info->alt_frac,
                lci_info->alt_integ, lci_info->alt_frac);
        gid0 = &rrmstats->ni_rrm_stats.gid0;
        fprintf(fd, "GID0 stats: \n");
        fprintf(fd, "\t\t txfragcnt %d mcastfrmcnt %d failcnt %d rxfragcnt %d mcastrxfrmcnt %d \n",
                gid0->txfragcnt, gid0->mcastfrmcnt, gid0->failcnt,gid0->rxfragcnt,gid0->mcastrxfrmcnt);
        fprintf(fd, "\t\t fcserrcnt %d  txfrmcnt %d\n",  gid0->fcserrcnt, gid0->txfrmcnt);
        gid1 = &rrmstats->ni_rrm_stats.gid1;
        fprintf(fd, "GID1 stats: \n");
        fprintf(fd, "\t\t rty %d multirty %d frmdup %d rtsuccess %d rtsfail %d ackfail %d\n", gid1->rty, gid1->multirty,gid1->frmdup,
                gid1->rtsuccess, gid1->rtsfail, gid1->ackfail);
        for (i = 0; i < 8; i++)
        {
            gidupx = &rrmstats->ni_rrm_stats.gidupx[i];
            fprintf(fd, "dup stats[%d]: \n", i);
            fprintf(fd, "\t\t qostxfragcnt %d qosfailedcnt %d qosrtycnt %d multirtycnt %d\n"
                    "\t\t qosfrmdupcnt %d qosrtssuccnt %d qosrtsfailcnt %d qosackfailcnt %d\n"
                    "\t\t qosrxfragcnt %d qostxfrmcnt %d qosdiscadrfrmcnt %d qosmpdurxcnt %d qosrtyrxcnt %d \n",
                    gidupx->qostxfragcnt,gidupx->qosfailedcnt,
                    gidupx->qosrtycnt,gidupx->multirtycnt,gidupx->qosfrmdupcnt,
                    gidupx->qosrtssuccnt,gidupx->qosrtsfailcnt,gidupx->qosackfailcnt,
                    gidupx->qosrxfragcnt,gidupx->qostxfrmcnt,gidupx->qosdiscadrfrmcnt,
                    gidupx->qosmpdurxcnt,gidupx->qosrtyrxcnt);
        }
        gid10 = &rrmstats->ni_rrm_stats.gid10;
        fprintf(fd, "GID10 stats: \n");
        fprintf(fd, "\t\tap_avg_delay %d be_avg_delay %d bk_avg_delay %d\n"
                "vi_avg_delay %d vo_avg_delay %d st_cnt %d ch_util %d\n",
                gid10->ap_avg_delay,gid10->be_avg_delay,gid10->bk_avg_delay,
                gid10->vi_avg_delay,gid10->vo_avg_delay,gid10->st_cnt,gid10->ch_util);
        tsmdata = &rrmstats->ni_rrm_stats.tsm_data;
        fprintf(fd, "TSM data : \n");
        fprintf(fd, "\t\ttid %d brange %d mac:%02x:%02x:%02x:%02x:%02x:%02x tx_cnt %d\n",tsmdata->tid,tsmdata->brange,
                tsmdata->mac[0],tsmdata->mac[1],tsmdata->mac[2],tsmdata->mac[3],tsmdata->mac[4],tsmdata->mac[5],tsmdata->tx_cnt);
        fprintf(fd,"\t\tdiscnt %d multirtycnt %d cfpoll %d qdelay %d txdelay %d bin[0-5]: %d %d %d %d %d %d\n\n",
                tsmdata->discnt,tsmdata->multirtycnt,tsmdata->cfpoll,
                tsmdata->qdelay,tsmdata->txdelay,tsmdata->bin[0],tsmdata->bin[1],tsmdata->bin[2],
                tsmdata->bin[3],tsmdata->bin[4],tsmdata->bin[5]);
        lmdata = &rrmstats->ni_rrm_stats.lm_data;
        fprintf(fd, "Link Measurement information :\n");
        fprintf(fd, "\t\ttx_pow %d lmargin %d rxant %d txant %d rcpi %d rsni %d\n\n",
                lmdata->tx_pow,lmdata->lmargin,lmdata->rxant,lmdata->txant,
                lmdata->rcpi,lmdata->rsni);
        fprintf(fd, "Frame Report Information : \n\n");
        for (i = 0; i < 12; i++)
        {
            frmcnt = &rrmstats->ni_rrm_stats.frmcnt_data[i];
            fprintf(fd,"Transmitter MAC: %02x:%02x:%02x:%02x:%02x:%02x",frmcnt->ta[0], frmcnt->ta[1],frmcnt->ta[2],frmcnt->ta[3],frmcnt->ta[4],frmcnt->ta[5]);
            fprintf(fd," BSSID: %02x:%02x:%02x:%02x:%02x:%02x",frmcnt->bssid[0], frmcnt->bssid[1], frmcnt->bssid[2],\
                    frmcnt->bssid[3], frmcnt->bssid[4],frmcnt->bssid[5]);
            fprintf(fd," phytype %d arsni %d lrsni %d lrcpi %d antid %d frame count %d\n",
                    frmcnt->phytype,frmcnt->arcpi,frmcnt->lrsni,frmcnt->lrcpi,frmcnt->antid, frmcnt->frmcnt);
        }
    }
    return;
}

static void get_bcnrpt(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s;
    struct ieee80211req_athdbg req;
    ieee80211req_rrmstats_t *rrmstats_req;
    ieee80211_bcnrpt_t *bcnrpt = NULL;

    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return;
    }
    s = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_GETBCNRPT;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    bcnrpt  = (ieee80211_bcnrpt_t *) (malloc(sizeof(ieee80211_bcnrpt_t)));

    if(NULL == bcnrpt) {
        printf("insufficient memory \n");
        close(s);
        return;
    }

    rrmstats_req = &req.data.rrmstats_req;
    rrmstats_req->data_addr = (void *) bcnrpt;
    rrmstats_req->data_size = (sizeof(ieee80211_bcnrpt_t));
    rrmstats_req->index = 1;

    printf("\t BSSID \t\t\tCHNUM\tRCPI \n");
    while(rrmstats_req->index) {
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: ieee80211_dbgreq_bcnrpt failed");
        }

        if (bcnrpt->more) {
            rrmstats_req->index++;
            printf(" \t%02x %02x %02x %02x %02x %02x\t %d \t %d \n",
                    bcnrpt->bssid[0],bcnrpt->bssid[1],
                    bcnrpt->bssid[2],bcnrpt->bssid[3],
                    bcnrpt->bssid[4],bcnrpt->bssid[5],
                    bcnrpt->chnum,bcnrpt->rcpi);
        } else {
            rrmstats_req->index = 0;
        }
    }

    close(s);
    free(bcnrpt);
    return;
}
static void get_rssi(const char *ifname, int argc, char *argv[])
{

    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if ((argc < 4) || (argc > 4))
    {
        usage_getrssi();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }



    req.cmd = IEEE80211_DBGREQ_GETRRSSI;

    req.dstmac[0] = 0x00;
    req.dstmac[1] = 0x00;
    req.dstmac[2] = 0x00;
    req.dstmac[3] = 0x00;
    req.dstmac[4] = 0x00;
    req.dstmac[5] = 0x00;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6))
    {
        errx(1, "Invalid mac address");
        return;
    }
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));


    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0)
    {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_RRMSTATSREQ failed");
    }
    close(s);
}

static void channel_loading_channel_list_set(const char *ifname, int argc, char *argv[])
{
#define MIN_PARAM  4
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    ieee80211_user_chanlist_t chanlist;
    u_int8_t *chan  = NULL ; /*user channel list */

    if ((argc < MIN_PARAM))
    {
        usage_setchanlist();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_SETACSUSERCHANLIST;
    chan = (u_int8_t *) malloc(sizeof(u_int8_t) * (argc - 3));

    if(NULL == chan) {
        close(s);
        return;
    }

    chanlist.chan = chan;
    chanlist.n_chan = 0;
    req.data.param[0] = (int )&chanlist; /*typecasting to avoid warning */

    for(i = 3;i < argc; i++)
        chan[i - 3] =  atoi(argv[i]);

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0)
    {
        errx(1, "ieee80211_ioctl_dbgreq: ieee80211_dbgreq_setchanlist failed");
        printf("error in ioctl \n");
    }

    free(chan);
    close(s);
    return;
#undef MIN_PARAM
}
static void set_usr_ctrl_tbl(const char *ifname, int argc, char *argv[])
{
#define MIN_CTRL_PARAM_COUNT  4
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    ieee80211_user_ctrl_tbl_t  ctrl_tbl;
    u_int16_t array_len = 0;
    u_int8_t *ctrl_array  = NULL ; /*user control table */

    if ((argc < MIN_CTRL_PARAM_COUNT)) {
        usage_set_usr_ctrl_tbl();
        return;
    }

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));

    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    array_len = argc - 3;
    req.cmd = IEEE80211_DBGREQ_SETSUSERCTRLTBL;
    ctrl_array = (u_int8_t *) malloc(sizeof(u_int8_t) * array_len);

    if(NULL == ctrl_array) {
        close(s);
        return;
    }

    ctrl_tbl.ctrl_array = ctrl_array;
    ctrl_tbl.ctrl_len = array_len;
    req.data.param[0] = (int )&ctrl_tbl; /*typecasting to avoid warning */

    for(i = 3;i < argc; i++) {
        ctrl_array[i - 3] =  atoi(argv[i]);
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "ieee80211_ioctl_dbgreq: IEEE80211_DBGREQ_SETSUSERCTRLTBL failed");
        printf("error in ioctl \n");
    }

    free(ctrl_array);
    close(s);
    return;
#undef MIN_CTRL_PARAM_COUNT
}

static void channel_loading_channel_list_get(const char *ifname, int argc, char *argv[])
{
#define MAX_PARAM  3
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    ieee80211_user_chanlist_t chanlist;
    u_int8_t *chan  = NULL ; /*user channel list */

    if ((argc > MAX_PARAM))
    {
        usage_getchanlist();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_GETACSUSERCHANLIST;

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    chan = (u_int8_t *) malloc(sizeof(u_int8_t) * (255));
    if(chan == NULL) {
        close(s);
        return;
    }

    chanlist.chan = chan;
    chanlist.n_chan = 0;
    req.data.param[0] = (int )&chanlist; /*typecasting to avoid warning */

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0)
    {
        errx(1, "ieee80211_ioctl_dbgreq: ieee80211_dbgreq_getchanlist failed");
        printf("error in ioctl \n");
        free(chan);
        close(s);
        return;
    }
    printf("Following list used in channel load report \n");

    for(i = 0;i < chanlist.n_chan;i++)
        printf("%d    ",chanlist.chan[i]);

    printf("\n");

    free(chan);
    close(s);
    return;
#undef MAX_PARAM
}

/**
 * @brief to calulate power used by block channel list
 *
 * @param a
 * @param b
 *
 * @return
 */

static inline int power(int a, int b )
{
    int number = 1,i = 0;
    for (i = 0;i < b;i++)
        number *= a;
    return number;
}
/**
 * @brief To display the MAC address of the RRM capable STA
 *
 * @return
 */
static void rrm_sta_list(const char *ifname, int argc, char *argv[])
{
#define MAX_CLIENTS 256
#define MAX_PARAM 3
    struct ieee80211req_athdbg req = { 0 };
    struct iwreq iwr = { 0 };
    int s = 0,count = 0,index;
    unsigned char *addr_list = NULL;
    ieee80211_rrm_sta_info_t *rrm_stats;
    if (argc > MAX_PARAM)
    {
        usage_rrmstalist();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    rrm_stats = (void *)malloc(sizeof(ieee80211_rrm_sta_info_t));
    req.cmd = IEEE80211_DBGREQ_GET_RRM_STA_LIST;
    req.data.param[0] = (int )rrm_stats;
    memset(req.dstmac,0xff,IEEE80211_ADDR_LEN); /* Assigning broadcast address to get the STA count */

    if(rrm_stats == NULL) {
        printf("Memory allocation failed  __investigate__\n");
        close(s);
        return;
    }

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("set RRM STA list  failed \n");
        goto MEMORY_FAIL;
    }
    if(rrm_stats->count > MAX_CLIENTS) {
        perror("can not display long list __investigate__\n");
        goto MEMORY_FAIL;
    }
    addr_list = (u_int8_t *) malloc(IEEE80211_ADDR_LEN * (rrm_stats->count));
    if(addr_list == NULL) {
        perror("Memory allocation failed  __investigate__\n");
        goto MEMORY_FAIL;
    }
    count = rrm_stats->count;
    req.data.param[1] = (int) addr_list; /*typecasted to avoid warning */
    memset(req.dstmac,0x00,IEEE80211_ADDR_LEN);
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("RRM STA LIST failed \n");
        free(addr_list);
        goto MEMORY_FAIL;
    }
    printf("\t RRM Capable station's Mac address ");
    for(index = 0;index<(IEEE80211_ADDR_LEN*count);index++){
        if(!(index%6))
            printf("\n");
        printf("%02x:",addr_list[index]);
    }
    printf( "\n");
#undef MAX_PARAM
#undef MAX_CLIENTS
    free(addr_list);
MEMORY_FAIL:
    free(rrm_stats);
    close(s);
    return;
}
#if QCA_LTEU_SUPPORT
static int ret_frm_thd;
#endif
/*
 *
 * Function to get the traffic statistics like rssi,minimum rssi,maximum rssi and median rssi
 * of each connected node from the driver and display the values
 *
 */
static void display_traffic_statistics(const char *ifname, int argc, char *argv[])
{
#define MAX_PARAM 3
    struct ieee80211req_athdbg req = { 0 };
    struct iwreq iwr = { 0 };
    int s = 0,count = 0,bin_number = 0 ,traffic_rate,index;
    unsigned char *addr_list = NULL;
    ieee80211_noise_stats_t *noise_stats;
    ieee80211_node_info_t *node_info;
    int bin_index,bin_stats = 0 ;
    if (argc > MAX_PARAM)
    {
        usage_display_traffic_statistics();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    node_info = (void *)malloc(sizeof(ieee80211_node_info_t));

    if(node_info == NULL) {
        printf("Memory allocation failed  __investigate__\n");
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_DISPLAY_TRAFFIC_STATISTICS;
    req.data.param[0] = (int )node_info;
    memset(req.dstmac,0xff,IEEE80211_ADDR_LEN); /* Assigning broadcast address to get the STA count */

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("display traffic_statistics  failed \n");
        goto MEMORY_FAIL;
    }
    count = node_info->count;
    bin_number = node_info->bin_number;
    traffic_rate = node_info->traf_rate;

    addr_list = (u_int8_t *) malloc(IEEE80211_ADDR_LEN * (count));
    if(addr_list == NULL) {
        printf("Memory allocation failed for storing the address  __investigate__\n");
        goto MEMORY_FAIL;
    }

    noise_stats = (ieee80211_noise_stats_t *) malloc(sizeof(ieee80211_noise_stats_t) * bin_number * count);
    if(noise_stats == NULL) {
        printf("Memory allocation failed for storing the noise statistics  __investigate__\n");
        free (addr_list);
        goto MEMORY_FAIL;
    }

    req.data.param[1] = (int)addr_list; /*typecasted to avoid warning */
    req.data.param[3] = (int)noise_stats;
    memset(req.dstmac,0x00,IEEE80211_ADDR_LEN);
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("Traffic statistics display failed \n");
        goto MEMORY_FAIL2;
    }
    for(index = 0;index<(IEEE80211_ADDR_LEN*count);index++){
        if (index % IEEE80211_ADDR_LEN == 0){
            printf("Mac address \t");
        }
        printf("%02x:",addr_list[index]);
    if (index % 6 == (IEEE80211_ADDR_LEN-1)){
        printf("\n");
            for(bin_index = 0; (bin_index < bin_number) && bin_stats <(count * bin_number);bin_index++,bin_stats++)
            {
                printf(" At %d sec : NOISE value is %d MIN value is %d MAX value is %d  MEDIAN value is %d\n",(traffic_rate)*(bin_index+1), noise_stats[bin_stats].noise_value,noise_stats[bin_stats].min_value,noise_stats[bin_stats].max_value,noise_stats[bin_stats].median_value);
            }
        }
    }
MEMORY_FAIL2:
#undef MAX_PARAM
    free(addr_list);
    free(noise_stats);
MEMORY_FAIL:
    free(node_info);
    close(s);
    return;
}
/*
 * Parse event sent using wireless_send_event()
 */
static void *
get_next_wireless_custom_event(void *event_v)
{
#if QCA_LTEU_SUPPORT
    int sock;
    struct sockaddr_nl local;
    struct sockaddr_nl from;
    socklen_t fromlen;
    int len;
    char buf[8192];
    struct nlmsghdr *h;
    int done, count;
    fd_set r;
    struct timeval to;
    int *event = (int *)event_v;

    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket:\n");
        return NULL;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind:\n");
        close(sock);
        return NULL;
    }

    count = 0;
    do {
        done = 0;
        FD_ZERO(&r);
        FD_SET(sock, &r);
        to.tv_sec = 1;
        to.tv_usec = 0;
        if (select(sock + 1, &r, NULL, NULL, &to) < 0) {
            perror("select:\n");
            close(sock);
            return NULL;
        }
        if (ret_frm_thd) {
            close(sock);
            return NULL;
        }
        if (!FD_ISSET(sock, &r)) {
            continue;
        }
        memset(&from, 0, sizeof(from));
        fromlen = sizeof(from);

        len = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
        if (len < 0) {
            perror("recvfrom:\n");
            close(sock);
            return NULL;
        }
        h = (struct nlmsghdr *)buf;
        while (NLMSG_OK(h, len)) {
            struct ifinfomsg *ifi;
            if (h->nlmsg_type != RTM_NEWLINK) {
                h = NLMSG_NEXT(h, len);
                continue;
            }
            ifi = NLMSG_DATA(h);
            if (NLMSG_PAYLOAD(h, 0) >= sizeof(struct ifinfomsg)) {
                struct rtattr *attr = (struct rtattr *)((char *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
                int attrlen = NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg));
                int rlen = RTA_ALIGN(sizeof(struct rtattr));
                while (RTA_OK(attr, attrlen)) {
                    struct iw_event iwe;
                    char *start;
                    char *end;
                    if (attr->rta_type != IFLA_WIRELESS) {
                        attr = RTA_NEXT(attr, attrlen);
                        continue;
                    }
                    start = ((char *)attr) + rlen;
                    end = start + (attr->rta_len - rlen);
                    while (start + IW_EV_LCP_LEN <= end) {
                        memcpy(&iwe, start, IW_EV_LCP_LEN);
                        if (iwe.len <= IW_EV_LCP_LEN) {
                            break;
                        }
                        if ((iwe.cmd == IWEVCUSTOM) || (iwe.cmd == IWEVGENIE)) {
                            char *pos = (char *)&iwe.u.data.length;
                            char *data = start + IW_EV_POINT_LEN;
                            memcpy(pos, start + IW_EV_LCP_LEN, sizeof(struct iw_event) - (pos - (char *)&iwe));
                            if (data + iwe.u.data.length <= end) {
                                if (*event == IEEE80211_EV_SCAN && iwe.u.data.flags == *event &&
                                    iwe.u.data.length >= sizeof(struct event_data_scan)) {
                                    struct event_data_scan *scan = (struct event_data_scan *)data;
                                    printf("Scan completion event:\n");
                                    printf("req_id=%d\n", scan->scan_req_id);
                                    printf("status=%d\n", scan->scan_status);
                                    done = 1;
                                } else if (*event == IEEE80211_EV_MU_RPT && iwe.u.data.flags == *event &&
                                           iwe.u.data.length >= sizeof(struct event_data_mu_rpt)) {
                                    int i;
                                    struct event_data_mu_rpt *mu_rpt = (struct event_data_mu_rpt *)data;
                                    printf("MU report event:\n");
                                    printf("req_id=%d\n", mu_rpt->mu_req_id);
                                    printf("channel=%d\n", mu_rpt->mu_channel);
                                    printf("status=%d\n", mu_rpt->mu_status);
                                    for (i = 0; i < (MU_MAX_ALGO-1); i++)
                                        printf("total_val[%d]=%d\n", i, mu_rpt->mu_total_val[i]);
                                    printf("num_bssid=%d\n", mu_rpt->mu_num_bssid);
                                    printf("actual_duration=%d\n", mu_rpt->mu_actual_duration);
                                    printf("mu_hidden_node=");
                                    for (i = 0; i < LTEU_MAX_BINS; i++)
                                        printf("%d ",mu_rpt->mu_hidden_node_algo[i]);
                                    printf("\n");

                                    printf("num_ta_entries=%d\n",mu_rpt->mu_num_ta_entries);

                                    for (i = 0; i < mu_rpt->mu_num_ta_entries; i++) {
                                        printf("TA_MU_entry[%d]= ",i);
                                        printf("device_type=");
                                        switch(mu_rpt->mu_database_entries[i].mu_device_type) {
                                            case 0:
                                                   printf("AP ");
                                                   break;
                                            case 1:
                                                   printf("STA ");
                                                   break;
                                            case 2:
                                                   printf("SC_SAME_OP ");
                                                   break;
                                            case 3:
                                                   printf("SC_DIFF_OP ");
                                                   break;
                                            default:
                                                   printf("Unknown ");
                                        }
                                        printf("BSSID=%02x:%02x:%02x:%02x:%02x:%02x ",
                                                mu_rpt->mu_database_entries[i].mu_device_bssid[0],
                                                mu_rpt->mu_database_entries[i].mu_device_bssid[1],
                                                mu_rpt->mu_database_entries[i].mu_device_bssid[2],
                                                mu_rpt->mu_database_entries[i].mu_device_bssid[3],
                                                mu_rpt->mu_database_entries[i].mu_device_bssid[4],
                                                mu_rpt->mu_database_entries[i].mu_device_bssid[5]);
                                        printf("TA_mac_address=%02x:%02x:%02x:%02x:%02x:%02x ",
                                                mu_rpt->mu_database_entries[i].mu_device_macaddr[0],
                                                mu_rpt->mu_database_entries[i].mu_device_macaddr[1],
                                                mu_rpt->mu_database_entries[i].mu_device_macaddr[2],
                                                mu_rpt->mu_database_entries[i].mu_device_macaddr[3],
                                                mu_rpt->mu_database_entries[i].mu_device_macaddr[4],
                                                mu_rpt->mu_database_entries[i].mu_device_macaddr[5]);
                                        printf("Average_duration=%d ",mu_rpt->mu_database_entries[i].mu_avg_duration);
                                        printf("Average_RSSI=%d ",mu_rpt->mu_database_entries[i].mu_avg_rssi);
                                        printf("MU_percent=%d\n",mu_rpt->mu_database_entries[i].mu_percentage);
                                    }
                                    done = 1;
                                }
                            }
                        }
                        start += iwe.len;
                    }
                    attr = RTA_NEXT(attr, attrlen);
                }
            }
            h = NLMSG_NEXT(h, len);
        }
        ++count;
    } while(!done && count <= MAX_NUM_TRIES);

    close(sock);
#endif
    return NULL;
}

/*
 * Handle scan params / mu params.
 * Used for LTEu.
 */
static void lteu_param(const char *ifname, int argc, char *argv[])
{
#if QCA_LTEU_SUPPORT
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (streq(argv[2], "rpt_prb_time")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }
    } else if (streq(argv[2], "g_rpt_prb_time")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME;
        req.data.param[0] = 0;
        if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("ioctl:\n");
        }
        printf("%s: %u\n", argv[2], req.data.param[1]);
    } else if (streq(argv[2], "rest_time")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_REST_TIME;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }
    } else if (streq(argv[2], "g_rest_time")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_REST_TIME;
        req.data.param[0] = 0;
        if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("ioctl:\n");
        }
        printf("%s: %u\n", argv[2], req.data.param[1]);
    } else if (streq(argv[2], "idle_time")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_IDLE_TIME;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }
    } else if (streq(argv[2], "g_idle_time")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_IDLE_TIME;
        req.data.param[0] = 0;
        if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("ioctl:\n");
        }
        printf("%s: %u\n", argv[2], req.data.param[1]);
    } else if (streq(argv[2], "prb_delay")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_PROBE_DELAY;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }
    } else if (streq(argv[2], "g_prb_delay")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_PROBE_DELAY;
        req.data.param[0] = 0;
        if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("ioctl:\n");
        }
        printf("%s: %u\n", argv[2], req.data.param[1]);
    } else if (streq(argv[2], "mu_delay")) {
        req.cmd = IEEE80211_DBGREQ_MU_DELAY;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }
    } else if (streq(argv[2], "g_mu_delay")) {
        req.cmd = IEEE80211_DBGREQ_MU_DELAY;
        req.data.param[0] = 0;
        if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("ioctl:\n");
        }
        printf("%s: %u\n", argv[2], req.data.param[1]);
    } else if (streq(argv[2], "sta_tx_pow")) {
        req.cmd = IEEE80211_DBGREQ_WIFI_TX_POWER;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }
    } else if (streq(argv[2], "g_sta_tx_pow")) {
        req.cmd = IEEE80211_DBGREQ_WIFI_TX_POWER;
        req.data.param[0] = 0;
        printf("%s: %u\n", argv[2], req.data.param[1]);

    } else if (streq(argv[2], "prb_spc_int")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_PROBE_SPACE_INTERVAL;
        req.data.param[0] = 1;
        if (argc >= 4) {
            req.data.param[1] = strtoul(argv[3], NULL, 10);
            if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
                perror("ioctl:\n");
            }
        }

    } else if (streq(argv[2], "g_prb_spc_int")) {
        req.cmd = IEEE80211_DBGREQ_SCAN_PROBE_SPACE_INTERVAL;
        req.data.param[0] = 0;
        printf("%s: %u\n", argv[2], req.data.param[1]);
    }

    close(sock);
#endif
}

/*
 * wifitool athX lteu_cfg
 * [ -g 0|1 ] [ -n 1-10 ] [ -w 1-10 0-100+ ] [ -y 1-10 0-5000+ ] [ -t 1-10 (-110)-0+ ]
 * [ -o 10-10000 ] [ -f 0|1 ] [ -e 0|1 ] [ -h ]
 * -g : gpio start or not
 * -n : number of bins
 * -w : number of weights followed by the individual weights
 * -y : number of gammas followed by individual gammas
 * -t : number of thresholds followed by individual thresholds
 * -o : timeout
 * -f : 1 to use actual NF, 0 to use a hardcoded one
 * -e : 1 to include packets with PHY error code in MU computation, 0 to exclude them
 * -h : help
 */
static void lteu_cfg(const char *ifname, int argc, char *argv[])
{
#if QCA_LTEU_SUPPORT
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int sock;
    int i, j, n, x, y;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_LTEU_CFG;
    req.data.lteu_cfg.lteu_gpio_start = 0;
    req.data.lteu_cfg.lteu_num_bins = LTEU_MAX_BINS;
    for (i = 0; i < LTEU_MAX_BINS; i++) {
        req.data.lteu_cfg.lteu_weight[i] = 49;
        req.data.lteu_cfg.lteu_thresh[i] = 90;
        req.data.lteu_cfg.lteu_gamma[i] = 51;
    }
    req.data.lteu_cfg.lteu_scan_timeout = 10;
    req.data.lteu_cfg.use_actual_nf = 0;
    req.data.lteu_cfg.lteu_cfg_reserved_1 = 1;
    argc -= 3;
    j = 3;
    while (argc) {
        if (!strcmp(argv[j], "-g")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 0 && x <= 1) {
                argc--;
                j++;
                req.data.lteu_cfg.lteu_gpio_start = x;
            }
        } else if (!strcmp(argv[j], "-n")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 1 && x <= 10) {
                argc--;
                j++;
                req.data.lteu_cfg.lteu_num_bins = x;
            }
        } else if (!strcmp(argv[j], "-w")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 1 && x <= 10) {
                argc--;
                j++;
                n = x;
                i = 0;
                while (n-- && argc) {
                    y = strtoul(argv[j], NULL, 10);
                    if (y >= 0 && y <= 100) {
                        argc--;
                        j++;
                        req.data.lteu_cfg.lteu_weight[i++] = y;
                    } else
                        break;
                }
                if (i != x) {
                    for (i = 0; i < LTEU_MAX_BINS; i++)
                        req.data.lteu_cfg.lteu_weight[i] = 49;
                }
            }
        } else if (!strcmp(argv[j], "-y")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 1 && x <= 10) {
                argc--;
                j++;
                n = x;
                i = 0;
                while (n-- && argc) {
                    y = strtoul(argv[j], NULL, 10);
                    if (y >= 0 && y <= 5000) {
                        argc--;
                        j++;
                        req.data.lteu_cfg.lteu_gamma[i++] = y;
                    } else
                        break;
                }
                if (i != x) {
                    for (i = 0; i < LTEU_MAX_BINS; i++)
                        req.data.lteu_cfg.lteu_gamma[i] = 51;
                }
            }
        } else if (!strcmp(argv[j], "-t")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 1 && x <= 10) {
                argc--;
                j++;
                n = x;
                i = 0;
                while (n-- && argc) {
                    y = strtoul(argv[j], NULL, 10);
                    if (y >= -110 && y <= 0) {
                        argc--;
                        j++;
                        req.data.lteu_cfg.lteu_thresh[i++] = y;
                    } else
                        break;
                }
                if (i != x) {
                    for (i = 0; i < LTEU_MAX_BINS; i++)
                        req.data.lteu_cfg.lteu_thresh[i] = 90;
                }
            }
        } else if (!strcmp(argv[j], "-o")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 10 && x <= 10000) {
                argc--;
                j++;
                req.data.lteu_cfg.lteu_scan_timeout = x;
            }
        } else if (!strcmp(argv[j], "-f")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x >= 0 && x <= 1) {
                argc--;
                j++;
                req.data.lteu_cfg.use_actual_nf = x;
            }
        } else if (!strcmp(argv[j], "-e")) {
            argc--;
            j++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[j], NULL, 10);
            if (x == 0 || x == 1) {
                argc--;
                j++;
                req.data.lteu_cfg.lteu_cfg_reserved_1 = x;
            }
        } else if (!strcmp(argv[j], "-h")) {
            argc--;
            j++;
            printf("wifitool athX lteu_cfg "
                   "[ -g 0|1 ] [ -n 1-10 ] [ -w 1-10 0-100+ ] [ -y 1-10 -0-5000+ ] "
                   "[ -t 1-10 (-110)-0+ ] [ -o 10-10000 ] [ -f 0|1 ] [ -e 0|1 ] [ -h ]\n");
            printf("-g : gpio start or not\n");
            printf("-n : number of bins\n");
            printf("-w : number of weights followed by the individual weights\n");
            printf("-y : number of gammas followed by the individual gammas\n");
            printf("-t : number of thresholds followed by the individual thresholds\n");
            printf("-o : timeout\n");
            printf("-f : 1 to use actual NF, 0 to use a hardcoded one\n");
            printf("-e : 1 to include erroneous packets in MU calculation, 0 to exclude\n");
            printf("-h : help\n");
            close(sock);
            return;
        } else {
            argc--;
            j++;
        }
    }
    if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("ioctl:\n");
    }

    close(sock);
#endif
}

static void atf_debug_nodestate(const char *ifname, int argc, char *argv[])
{
#if QCA_AIRTIME_FAIRNESS
#define ATH_NUM_TID 17

    struct iwreq iwr;
    int sock;
    struct ieee80211req_athdbg req;
    int ret, i;
    u_int32_t nodestate = 0;

    if (argc < 4) {
        printf("usage: wifitool athX atf_debug_nodestate <mac addr>\n");
        return;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_ATF_DUMP_NODESTATE;
    req.data.atf_dbg_req.ptr = &nodestate;
    if (!wifitool_mac_aton(argv[3], req.dstmac, sizeof(req.dstmac))) {
        printf("invalid mac address\n");
        close(sock);
        return;
    }

    ret = ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr);
    if (ret < 0) {
        perror("ioctl:\n");
        close(sock);
        return;
    }

    printf("Node state : 0x%x \n", nodestate);
    for( i = 0; i < ATH_NUM_TID; i++)
    {
        if( (nodestate >> i) & 0x1)
        {
            printf("tid : %d paused \n", i);
        }
    }
    close(sock);
#endif
}

/*
 * Dump the history logged of ATF stats
 */
static void atf_dump_debug(const char *ifname, int argc, char *argv[])
{
#if QCA_AIRTIME_FAIRNESS
    struct iwreq iwr;
    int sock;
    struct ieee80211req_athdbg req;
    int ret, i;
    unsigned int size, id;
    u_int32_t *ptr;
    struct atf_stats *stats;

    if (argc < 4) {
        printf("usage: wifitool athX atf_dump_debug <mac addr>\n");
        return;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_ATF_DUMP_DEBUG;
    size = 1024 * sizeof(struct atf_stats);
    ptr = malloc((sizeof(u_int32_t) * 2) + size);
    if (!ptr) {
        printf("out of memory\n");
        close(sock);
        return;
    }
    memset(ptr, 0, (sizeof(u_int32_t) * 2) + size);
    req.data.atf_dbg_req.ptr = ptr;
    req.data.atf_dbg_req.size = (sizeof(u_int32_t) * 2) + size;
    if (!wifitool_mac_aton(argv[3], req.dstmac, sizeof(req.dstmac))) {
        printf("invalid mac address\n");
        free(ptr);
        close(sock);
        return;
    }

    ret = ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr);
    if (ret < 0) {
        perror("ioctl:\n");
        free(ptr);
        close(sock);
        return;
    }

    size = ptr[0] / sizeof(struct atf_stats);
    id = ptr[1];
    stats = (struct atf_stats *)&ptr[2];

    printf("                     total   actual            actual                      total                        max      min    nobuf   txbufs  txbytes                           \n");
    printf("    time    allot    allot    allot   common   common   unused  contrib  contrib   borrow    allow     held     held     drop     sent     sent      wup  raw-tok max-tput\n");
    for (i = 0; i < size; i++) {
        printf("%8u %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d\n",
           stats[id].timestamp, stats[id].tokens,
           stats[id].total, stats[id].act_tokens,
           stats[id].tokens_common, stats[id].act_tokens_common,
           stats[id].unused, stats[id].contribution,
           stats[id].tot_contribution, stats[id].borrow,
           stats[id].allowed_bufs, stats[id].max_num_buf_held,
           stats[id].min_num_buf_held, stats[id].pkt_drop_nobuf,
           stats[id].num_tx_bufs, stats[id].num_tx_bytes,
           stats[id].weighted_unusedtokens_percent,
           stats[id].raw_tx_tokens, stats[id].throughput);

        id++;
        id &= (size - 1);
    }

    printf("debug history dumped\n");
    free(ptr);
    close(sock);
#endif
}

/*
 * Change the ATF log buffer size.
 */
static void atf_debug_size(const char *ifname, int argc, char *argv[])
{
#if QCA_AIRTIME_FAIRNESS
    struct iwreq iwr;
    int sock;
    struct ieee80211req_athdbg req;
    int ret;

    if (argc < 5) {
        printf("usage: wifitool athX atf_debug_size <mac addr> <size>\n");
        return;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_ATF_DEBUG_SIZE;
    if (!wifitool_mac_aton(argv[3], req.dstmac, sizeof(req.dstmac))) {
        printf("invalid mac address\n");
        close(sock);
        return;
    }
    req.data.param[0] = strtoul(argv[4], NULL, 10);

    ret = ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr);
    if (ret < 0) {
        perror("ioctl:\n");
        close(sock);
        return;
    }

    printf("log size changed\n");
    close(sock);
#endif
}

/*
 * wifitool athX ap_scan
 * [ -i 1-200 ] [ -c 1-32 36-165+ ] [ -p 0-100 ] [ -r 0-100 ]
 * [ -l 0-100 ] [ -t 0-100 ] [ -d 50-2000 ] [ -a 0|1 ] [ -w ] [ -h ]
 * -i : request id
 * -c : number of channels followed by IEEE number(s) of the channel(s)
 *      eg. to scan 36 and 40 #wifitool athX ap_scan -c 2 36 40
 * -p : scan repeat probe time
 * -r : scan rest time
 * -l : scan idle time
 * -t : scan probe delay
 * -d : channel time
 * -a : 1 for active scan, 0 for passive
 * -w : wait for wireless event
 * -h : help
 */
static void ap_scan(const char *ifname, int argc, char *argv[])
{
#if QCA_LTEU_SUPPORT
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int sock;
    int i, j, x, y;
    int ret;
    pthread_t thread;
    int wait_event = 0;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_AP_SCAN;
    req.data.ap_scan_req.scan_req_id = 1;
    req.data.ap_scan_req.scan_num_chan = 2;
    req.data.ap_scan_req.scan_channel_list[0] = 36;
    req.data.ap_scan_req.scan_channel_list[1] = 149;
    req.data.ap_scan_req.scan_type = SCAN_PASSIVE;
    req.data.ap_scan_req.scan_duration = 1000;
    req.data.ap_scan_req.scan_repeat_probe_time = (u_int32_t)-1;
    req.data.ap_scan_req.scan_rest_time = (u_int32_t)-1;
    req.data.ap_scan_req.scan_idle_time = (u_int32_t)-1;
    req.data.ap_scan_req.scan_probe_delay = (u_int32_t)-1;

    ret_frm_thd = 0;

    argc -= 3;
    i = 3;
    while (argc) {
        if (!strcmp(argv[i], "-i")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 1 && x <= 200) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_req_id = x;
            }
        } else if (!strcmp(argv[i], "-c")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 1 && x <= 32) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_num_chan = x;
                j = 0;
                while (x-- && argc) {
                    y = strtoul(argv[i], NULL, 10);
                    if (y >= 36 && y <= 165) {
                        argc--;
                        i++;
                        req.data.ap_scan_req.scan_channel_list[j++] = y;
                    } else
                        break;
                }
                if (j != req.data.ap_scan_req.scan_num_chan)
                    req.data.ap_scan_req.scan_num_chan = 0;
            }
        } else if (!strcmp(argv[i], "-p")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 100) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_repeat_probe_time = x;
            }
        } else if (!strcmp(argv[i], "-r")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 100) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_rest_time = x;
            }
        } else if (!strcmp(argv[i], "-l")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 100) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_idle_time = x;
            }
        } else if (!strcmp(argv[i], "-t")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 100) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_probe_delay = x;
            }
        } else if (!strcmp(argv[i], "-d")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 50 && x <= 2000) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_duration = x;
            }
        } else if (!strcmp(argv[i], "-a")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 1) {
                argc--;
                i++;
                req.data.ap_scan_req.scan_type = x;
            }
        } else if (!strcmp(argv[i], "-h")) {
            argc--;
            i++;
            printf("wifitool athX ap_scan "
                   "[ -i 1-200 ] [ -c 1-32 36-165+ ] [ -p 0-100 ] [ -r 0-100 ] "
                   "[ -l 0-100 ] [ -t 0-100 ] [ -d 50-2000 ] [ -a 0|1 ] [ -w ] [ -h ]\n");
            printf("-i : request id\n");
            printf("-c : number of channels followed by IEEE number(s) of the channel(s)\n");
            printf("     eg. to scan 36 and 40 #wifitool athX ap_scan -c 2 36 40\n");
            printf("-p : scan repeat probe time\n");
            printf("-r : scan rest time\n");
            printf("-l : scan idle time\n");
            printf("-t : scan probe delay\n");
            printf("-d : channel time\n");
            printf("-a : 1 for active scan, 0 for passive\n");
            printf("-w : wait for wireless event\n");
            printf("-h : help\n");
            close(sock);
            return;
        } else if (!strcmp(argv[i], "-w")) {
            argc--;
            i++;
            wait_event = IEEE80211_EV_SCAN;
        } else {
            argc--;
            i++;
        }
    }

    if (pthread_create(&thread, NULL, get_next_wireless_custom_event, &wait_event)) {
        printf("can't create thread\n");
        wait_event = 0;
    }

    ret = ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr);
    if (ret < 0) {
        perror("ioctl:\n");
    }

    close(sock);
    if (ret < 0 && wait_event) {
        ret_frm_thd = 1;
    }

    if (wait_event) {
        pthread_join(thread, NULL);
    }

#endif
}

/*
 * wifitool athX mu_scan
 * [ -i 1-200 ] [ -c 36-165 ] [ -t 1-15 ] [ -d 0-5000 ] [ -p 0-100 ] [ -b (-110)-0 ]
 * [ -s (-110)-0 ] [ -u (-110)-0 ] [ -m 00000-999999 ] [ -a 0-100 ] [ -w ] [ -h ]
 * -i : request id
 * -c : IEEE number of the channel
 * -t : algo(s) to use
 * -d : time
 * -p : LTEu Tx power
 * -b : RSSI threshold for AP
 * -s : RSSI threshold for STA
 * -u : RSSI threshold for SC
 * -m : the home PLMN ID is a 5 or 6 digit value
 * -a : alpha for num active bssid calc
 * -w : wait for wireless event
 * -h : help
 */
static void mu_scan(const char *ifname, int argc, char *argv[])
{
#if QCA_LTEU_SUPPORT
#define DEFAULT_PLMN_ID 0xFFFFFF
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int sock;
    int i, x;
    int ret;
    pthread_t thread;
    int wait_event = 0;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_MU_SCAN;
    req.data.mu_scan_req.mu_req_id = 1;
    req.data.mu_scan_req.mu_channel = 100;
    req.data.mu_scan_req.mu_type = MU_ALGO_1 | MU_ALGO_2 | MU_ALGO_3 | MU_ALGO_4;
    req.data.mu_scan_req.mu_duration = 1000;
    req.data.mu_scan_req.lteu_tx_power = 10;
    req.data.mu_scan_req.mu_rssi_thr_bssid = 90;
    req.data.mu_scan_req.mu_rssi_thr_sta   = 90;
    req.data.mu_scan_req.mu_rssi_thr_sc    = 90;
    req.data.mu_scan_req.home_plmnid = DEFAULT_PLMN_ID;
    req.data.mu_scan_req.alpha_num_bssid = 50;

    ret_frm_thd = 0;

    argc -= 3;
    i = 3;
    while (argc) {
        if (!strcmp(argv[i], "-i")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 1 && x <= 200) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_req_id = x;
            }
        } else if (!strcmp(argv[i], "-c")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 36 && x <= 165) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_channel = x;
            }
        } else if (!strcmp(argv[i], "-t")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 1 && x <= 15) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_type = x;
            }
        } else if (!strcmp(argv[i], "-d")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 5000) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_duration = x;
            }
        } else if (!strcmp(argv[i], "-p")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 100) {
                argc--;
                i++;
                req.data.mu_scan_req.lteu_tx_power = x;
            }
        } else if (!strcmp(argv[i], "-b")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= -110 && x <= 0) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_rssi_thr_bssid = x;
            }
        } else if (!strcmp(argv[i], "-s")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= -110 && x <= 0) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_rssi_thr_sta = x;
            }
        } else if (!strcmp(argv[i], "-u")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= -110 && x <= 0) {
                argc--;
                i++;
                req.data.mu_scan_req.mu_rssi_thr_sc = x;
            }
        } else if (!strcmp(argv[i], "-m")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 16);
            if (x > 0 && x <= DEFAULT_PLMN_ID) {
                argc--;
                i++;
                req.data.mu_scan_req.home_plmnid = x;
            }
        } else if (!strcmp(argv[i], "-a")) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 0 && x <= 100) {
                argc--;
                i++;
                req.data.mu_scan_req.alpha_num_bssid = x;
            }
        } else if (!strcmp(argv[i], "-h")) {
            argc--;
            i++;
            printf("wifitool athX mu_scan "
                   "[ -i 1-200 ] [ -c 36-165 ] [ -t 1-15 ] [ -d 0-5000 ] [ -p 0-100 ] "
                   "[ -b (-110)-0 ] [ -s (-110)-0 ] [ -u (-110)-0 ] [ -m 00000-999999 ] "
                   "[ -a 0-100 ] [ -w ] [ -h ]\n");
            printf("-i : request id\n");
            printf("-c : IEEE number of the channel\n");
            printf("-t : algo(s) to use\n");
            printf("-d : time\n");
            printf("-p : LTEu Tx power\n");
            printf("-b : RSSI threshold for AP\n");
            printf("-s : RSSI threshold for STA\n");
            printf("-u : RSSI threshold for SC\n");
            printf("-m : the home PLMN ID\n");
            printf("-a : alpha for num active bssid calc\n");
            printf("-w : wait for wireless event\n");
            printf("-h : help\n");
            close(sock);
            return;
        } else if (!strcmp(argv[i], "-w")) {
            argc--;
            i++;
            wait_event = IEEE80211_EV_MU_RPT;
        } else {
            argc--;
            i++;
        }
    }
#undef DEFAULT_PLMN_ID

    if (pthread_create(&thread, NULL, get_next_wireless_custom_event, &wait_event)) {
        printf("can't create thread\n");
        wait_event = 0;
    }

    ret = ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr);
    if (ret < 0) {
        perror("ioctl:\n");
    }

    close(sock);

    if (ret < 0 && wait_event) {
        ret_frm_thd = 1;
    }

    if (wait_event) {
        pthread_join(thread, NULL);
    }
#endif
}

/**
 * @brief api from user land to set block channel list to driver
 *
 * @param ifname
 * @param argc
 * @param argv[]
 */
static void block_acs_channel(const char *ifname, int argc, char *argv[])
{
#define MAX_CHANNEL 255
    int count = 0,temph = 0,cnt = 0,i = 0,j = 0,s = 0 ;
    u_int8_t channel[MAX_CHANNEL],valid[MAX_CHANNEL];
    char *p = NULL;
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    ieee80211_user_chanlist_t chanlist;
    u_int8_t *chan  = NULL ; /*user channel list */

    if ((argc < 4))
    {
        fprintf(stderr, "usage: wifitool athX block_acs_channel ch1.....chN\n");
        fprintf(stderr, "usage: wifitool athX block_acs_channel channels must be comma seperated \n");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_BLOCK_ACS_CHANNEL;
    memset(channel,0,MAX_CHANNEL);
    p = argv[3];
    while(*p != '\0') {
        while( *p != ',' && (*p != '\0'))
        {
            sscanf(p, "%1d", &temph);
            valid[i] = temph;
            p++;
            i++;
        }
        if(i) {
            for( cnt = 0;cnt < i;cnt++) {
                channel[count] = channel[count] + valid[cnt]*power(10,(i-cnt-1));
            }
            count++;
            i = 0;
            if(*p == '\0')
                break;
            else
                p++; /*by pass commma */
        }
        if(count >= MAX_CHANNEL) {
            count = MAX_CHANNEL;
            break;
        }
    }
    if(count) {
        chan = (u_int8_t *) malloc(sizeof(u_int8_t) * (count));
        if(NULL == chan) {
            close(s);
            return;
        }

        memcpy(chan,channel,count);
        chanlist.chan = chan;
        chanlist.n_chan = count;
        req.data.param[0] = (int )&chanlist; /*typecasting to avoid warning */

        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("set block channel list  failed \n");
            free(chan);
            close(s);
            return;
        }

        if(!chan[0])
            printf("List Flushed \n");
        else {
            printf("Following channels are blocked from Channel selection algorithm  \n");
            for(i = 0;i < count; i++) {
                printf("[%d] ",channel[i]);
            }
            printf("\n");
        }

    } else  {
        perror("Invalid channel list \n");
    }

    free(chan);
    close(s);
    return;
}

static void acs_report(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    struct ieee80211_acs_dbg *acs = NULL;
    if ((argc < 3) || (argc > 3))
    {
        usage_acsreport();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_GETACSREPORT;

    acs = (void *)malloc(sizeof(struct ieee80211_acs_dbg));

    if(NULL == acs) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    req.data.acs_rep.data_addr = acs;
    req.data.acs_rep.data_size = sizeof(struct ieee80211_acs_dbg);
    req.data.acs_rep.index = 0;
    acs->entry_id = 0;
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_RRMSTATSREQ failed");
        printf("error in ioctl \n");
        free(acs);
        close(s);
        return;
    }

    fprintf(stdout,"\n\nLegend: SC: Secondary Channel, WR: Weather Radar,"
                        "DFS: DFS Channel,\n        HN: High Noise, RSSI: Low RSSI,"
                        "CL: High Channel Load\n        RP: Regulatory Power,"
                        "N2G: Not selected 2G, P80X: Primary 80X80\n        "
                        "NS80X: Only for primary 80X80, NP80X: Only for Secondary 80X80\n\n");

    fprintf(stdout," The number of channels scanned for acs report is:  %d \n\n",acs->nchans);
    fprintf(stdout," Channel | BSS  | minrssi | maxrssi | NF | Ch load | spect load | sec_chan | Ranking | Unused\n");
    fprintf(stdout,"----------------------------------------------------------------------------------------------\n");
    /* output the current configuration */
    for (i = 0; i < acs->nchans; i++) {
        acs->entry_id = i;
        req.cmd = IEEE80211_DBGREQ_GETACSREPORT;
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("DBG req failed");
            free(acs);
            close(s);
            return;
        }
        /*To make sure we are not getting more than 100 %*/
        if(acs->chan_load  > 100)
            acs->chan_load = 100;

        fprintf(stdout," %4d(%3d) %4d     %4d      %4d   %4d    %4d        %4d       %4d       %4d      %s\n",
                acs->chan_freq,
                acs->ieee_chan,
                acs->chan_nbss,
                acs->chan_minrssi,
                acs->chan_maxrssi,
                acs->noisefloor,
                acs->chan_load,
                acs->channel_loading,
                acs->sec_chan,
                acs->acs_rank.rank,
                acs->acs_rank.desc);
    }

    free(acs);
    close(s);
    return;
}

static void get_rrmstats(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len,unicast=0;
    struct ieee80211req_athdbg req;
    ieee80211req_rrmstats_t *rrmstats_req;
    ieee80211_rrmstats_t *rrmstats = NULL;

    if ((argc < 3) || (argc > 4)) {
        usage_getrrrmstats();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_GETRRMSTATS;
    req.dstmac[0] = 0x00;
    req.dstmac[1] = 0x00;
    req.dstmac[2] = 0x00;
    req.dstmac[3] = 0x00;
    req.dstmac[4] = 0x00;
    req.dstmac[5] = 0x00;
    if (argc == 4) {
        unicast = 1;
        if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
            errx(1, "Invalid mac address");
            return;
        }
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    rrmstats = (ieee80211_rrmstats_t *)(malloc(sizeof(ieee80211_rrmstats_t)));

    if(NULL == rrmstats) {
        printf("insufficient memory \n");
        close(s);
        return;
    }

    rrmstats_req = &req.data.rrmstats_req;
    rrmstats_req->data_addr = (void *) rrmstats;
    rrmstats_req->data_size = (sizeof(ieee80211_rrmstats_t));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_RRMSTATSREQ failed");
    }
    print_rrmstats(stdout, rrmstats,unicast);

    free(rrmstats);
    close(s);
    return ;
}

static void send_frmreq(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_frame_req_info_t *frm_req = &req.data.frm_req;

    if (argc != 11)
    {
        usage_sendfrmreq();
        return;
    }

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_SENDFRMREQ;

    if (!wifitool_mac_aton(argv[3], frm_req->dstmac, 6))
    {
        errx(1, "Invalid mac address");
        return;
    }

    memcpy(req.dstmac, frm_req->dstmac, 6);
    frm_req->num_rpts = atoi(argv[4]);
    frm_req->regclass = atoi(argv[5]);
    frm_req->chnum = atoi(argv[6]);
    frm_req->r_invl = atoi(argv[7]);
    frm_req->m_dur = atoi(argv[8]);
    frm_req->ftype = atoi(argv[9]);

    if (!wifitool_mac_aton(argv[10], frm_req->peermac, 6))
    {
        errx(1, "Invalid mac address");
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0)
    {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDSTASTATSREQ failed");
    }
    close(s);
    return;
}

static void send_lcireq(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_lcireq_info_t *lci_req = &req.data.lci_req;

    if ((argc < 9) || (argc > 11) || (argc == 10))
    {
        usage_sendlcireq();
        return;
    }

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_SENDLCIREQ;

    if (!wifitool_mac_aton(argv[3], lci_req->dstmac, 6))
    {
        errx(1, "Invalid mac address");
        return;
    }

    memcpy(req.dstmac, lci_req->dstmac, 6);
    lci_req->num_rpts = atoi(argv[4]);
    lci_req->location = atoi(argv[5]);
    lci_req->lat_res = atoi(argv[6]);
    lci_req->long_res = atoi(argv[7]);
    lci_req->alt_res = atoi(argv[8]);

    if ((lci_req->lat_res > 34) || (lci_req->long_res > 34) ||
            (lci_req->alt_res > 30))
    {
        fprintf(stderr, "Incorrect number of resolution bits !!\n");
        usage_sendlcireq();
        exit(-1);
    }

    if (argc == 11)
    {
        lci_req->azi_res = atoi(argv[9]);
        lci_req->azi_type =  atoi(argv[10]);

        if (lci_req->azi_type !=1)
        {
            fprintf(stderr, "Incorrect azimuth type !!\n");
            usage_sendlcireq();
            exit(-1);
        }

        if (lci_req->azi_res > 9)
        {
            fprintf(stderr, "Incorrect azimuth resolution value(correct range 0 - 9) !!\n");
            usage_sendlcireq();
            exit(-1);
        }
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0)
    {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDSTASTATSREQ failed");
    }
    close(s);
    return;
}

    static void
send_stastats(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_stastats_info_t *stastats = &req.data.stastats;

    if (argc < 6) {
        usage_sendstastatsrpt();
    }
    else{
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDSTASTATSREQ;
        if (!wifitool_mac_aton(argv[3], stastats->dstmac, 6)) {
            errx(1, "Invalid mac address");
            return;
        }
        stastats->m_dur = atoi(argv[4]);
        stastats->gid = atoi(argv[5]);
        memcpy(req.dstmac,stastats->dstmac, 6);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0){
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDSTASTATSREQ failed");
        }
        close(s);
        return;
    }
}

static void
send_chload(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    ieee80211_rrm_chloadreq_info_t * chloadrpt = &req.data.chloadrpt;

    if ((argc < 9) || (argc > 11)) {
        usage_sendchloadrpt();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SENDCHLOADREQ;
        if (!wifitool_mac_aton(argv[3], chloadrpt->dstmac, 6)) {
            errx(1, "Invalid mac address");
            return;
        }
        chloadrpt->num_rpts = atoi(argv[4]);
        chloadrpt->regclass = atoi(argv[5]);
        chloadrpt->chnum = atoi(argv[6]);
        chloadrpt->r_invl = atoi(argv[7]);
        chloadrpt->m_dur  = atoi(argv[8]);
        if(argc > 9 ) { /*optional element */
            chloadrpt->cond  = atoi(argv[9]);
            chloadrpt->c_val  = atoi(argv[10]);
        }
        memcpy(req.dstmac, chloadrpt->dstmac, 6);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SENDCHLOADREQ failed");
        }
    }
    close(s);
    return;
}

static void tr069_chan_history(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, i = 0;
    struct ieee80211req_athdbg req;
    ieee80211_channelhist_t* chandata = NULL;
    char chanSelTime[40] = "\0";
    u_int8_t act_idx=0;
    struct tm tm;
    struct timespec *ts = NULL;
    struct timespec tstamp;
    struct timespec nowtime = {0};

    if ((argc < 3) || (argc > 3))
    {
        usage_tr069chanhist();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;
    chandata = (void *)malloc(sizeof(ieee80211_channelhist_t));

    if(NULL == chandata) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    memset(chandata, 0, sizeof(ieee80211_channelhist_t));
    req.data.tr069_req.data_addr = chandata;
    req.data.tr069_req.cmdid = TR069_CHANHIST;
    req.data.tr069_req.data_size = sizeof(ieee80211_channelhist_t);
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        free(chandata);
        close(s);
        return;
    }

    act_idx = chandata->act_index;
    fprintf(stdout," Channel | Selection Time \n");
    fprintf(stdout,"----------------------------------\n");
    /* print from latest to first */
    for(i = act_idx; i >= 0 ; i--) {
        clock_gettime(CLOCK_REALTIME, &nowtime);
        ts = &(chandata->chanlhist[i].chan_time);
        tstamp.tv_sec = nowtime.tv_sec - ts->tv_sec;
        /*Convert timespec to date/time*/
        if(tspectotime(&tstamp, &tm, chanSelTime, sizeof(chanSelTime)) < 0)
            goto err;
        fprintf(stdout," %4d      %s \n",
                chandata->chanlhist[i].chanid,chanSelTime);
    }
    if((act_idx < (IEEE80211_CHAN_MAXHIST - 1))
            && (chandata->chanlhist[act_idx+1].chanid)) {
        for(i = (IEEE80211_CHAN_MAXHIST - 1); i > act_idx ; i--) {
            clock_gettime(CLOCK_REALTIME, &nowtime);
            ts = &(chandata->chanlhist[i].chan_time);
            tstamp.tv_sec = nowtime.tv_sec - ts->tv_sec;
            /*Convert timespec to date/time*/
            if(tspectotime(&tstamp, &tm, chanSelTime, sizeof(chanSelTime)) < 0)
                goto err;
            fprintf(stdout," %4d      %s \n",
                    chandata->chanlhist[i].chanid,chanSelTime);
        }
    }

err:
    free(chandata);
    close(s);
    return;
}

static const char *
mac_to_string(const u_int8_t mac[IEEE80211_ADDR_LEN])
{
    static char a[18];
    int i;

    i = snprintf(a, sizeof(a), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (i < 17 ? NULL : a);
}

static void
get_assoc_time(const char *ifname, int argc, char *argv[])
{
    u_int8_t buf[24*1024];
    struct iwreq iwr;
    int s=0, len=0;
    u_int8_t *cp;
    struct timespec assoc_ts;
    struct timespec delta_ts;
    struct timespec now_ts = {0};
    struct tm assoc_tm = {0};
    char assoc_time[40]={'\0'};
    const char *mac_string = NULL;

    if (argc != 3) {
        fprintf(stderr, "usage: wifitool athX get_assoc_time");
        return;
    }

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) {
        fprintf(stderr, "Socket error");
        return;
    }
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(buf);
    if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0) {
        fprintf(stderr, "Unable to get station information");
        close(s);
        return;
    }
    len = iwr.u.data.length;
    if (len < sizeof(struct ieee80211req_sta_info)){
        fprintf(stderr, "Unable to get station information");
        close(s);
        return;
    }
    printf("%4s %9s\n"
            , "ADDR"
            , "ASSOCTIME"
          );
    cp = buf;
    do {
        struct ieee80211req_sta_info *si;
        si = (struct ieee80211req_sta_info *) cp;

        clock_gettime(CLOCK_REALTIME, &now_ts);
        (void) memcpy(&assoc_ts, &si->isi_tr069_assoc_time, sizeof(si->isi_tr069_assoc_time));
        delta_ts.tv_sec = now_ts.tv_sec - assoc_ts.tv_sec;
        if(tspectotime(&delta_ts, &assoc_tm, assoc_time, sizeof(assoc_time)) < 0)
            goto err;
        mac_string = mac_to_string(si->isi_macaddr);
        printf("%s %s"
                , (mac_string != NULL) ? mac_string :"NO MAC ADDR"
                , assoc_time
              );
        printf("\n");
        cp += si->isi_len, len -= si->isi_len;
    } while (len >= sizeof(struct ieee80211req_sta_info));

err:
    close(s);
    return;
}

static void tr069_txpower(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int percent_value, s = 0;
    int *txpower;
    if ((argc != 4))  {
        usage_tr069_txpower();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    txpower = (void *) malloc(sizeof(int));
    if(txpower == NULL){
        printf("Insufficient memory \n");
        close(s);
        return;
    }
    *txpower = 0;
    req.cmd = IEEE80211_DBGREQ_TR069;

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.data.tr069_req.cmdid = TR069_TXPOWER;
    req.data.tr069_req.data_addr = txpower;
    req.data.tr069_req.data_size = sizeof(int);

    percent_value = atoi(argv[3]);
    if ((percent_value > 100)||(percent_value < 0)){
        fprintf(stderr, "usage: Percentage value should be below 100 and more than 0 \n");
        free(txpower);
        close(s);
        return;
    }
    if (percent_value <= 100){
        req.data.param[0] = percent_value;
    }
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("set tr69_txpower  failed \n");
        free(txpower);
        close(s);
        return;
    }
    if(*txpower == -1){
        printf("This operation is not permitted when the Vap is up \n");
        free(txpower);
        close(s);
        return;
    }
    free(txpower);
    close(s);
    return;
}

static void tr069_gettxpower(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int value, s = 0;
    int *txpower;
    if ((argc != 3))  {
        usage_tr069_gettxpower();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    txpower = (void *) malloc(sizeof(int));
    if(txpower == NULL){
        printf("Insufficient memory \n");
        close(s);
        return;
    }
    *txpower = 0;
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GETTXPOWER;
    req.data.tr069_req.data_addr = txpower;
    req.data.tr069_req.data_size = sizeof(int);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("set tr69_txpower  failed \n");
        free(txpower);
        close(s);
        return;
    }
    if(*txpower == -1){
        printf("This operation is not permitted when the Vap is up \n");
        free(txpower);
        close(s);
        return;
    }

    printf(" %s:      TR69TXPOWER VALUE :      %d  \n", argv[1], *txpower);
    free(txpower);
    close(s);
    return;
}

static void tr069_guardintv(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int value, s = 0;
    if ((argc != 4)) {
        usage_tr069_guardintv();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    req.cmd = IEEE80211_DBGREQ_TR069;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.data.tr069_req.cmdid = TR069_GUARDINTV;
    value = atoi(argv[3]);
    req.data.param[0] = value;
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("set tr069_guardintv failed due to invalid input. Input should be either 800ns or 0 (auto) \n");
        close(s);
        return;
    }
    close(s);
    return;
}

static void tr069_get_guardintv(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    int *guardintv = NULL;
    if (argc != 3) {
        usage_tr069_get_guardintv();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    guardintv = (void *)malloc(sizeof(int));
    if(guardintv == NULL) {
        printf("insufficient memory");
        close(s);
        return;
    }
    *guardintv = 0;
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GET_GUARDINTV;
    req.data.tr069_req.data_addr = guardintv;
    req.data.tr069_req.data_size = sizeof(int);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("tr69_get_guardintv  failed \n");
        free(guardintv);
        close(s);
        return;
    }
    if(*guardintv == 0)
        printf(" %s:  TR69GUARDINTV VALUE:     %d (AUTO) \n",argv[1], *guardintv);
    else
        printf(" %s:  TR69GUARDINTV VALUE:     %d \n",argv[1], *guardintv);
    free(guardintv);
    close(s);
    return;
}

static void tr069_getassocsta(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    int *sta_count;
    if (argc != 3) {
        usage_tr069_getassocsta();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    sta_count = (void *) malloc(sizeof(int));
    if(sta_count == NULL) {
        printf("insufficient memory");
        close(s);
        return;
    }
    *sta_count = 0;
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GETASSOCSTA_CNT;
    req.data.tr069_req.data_addr = sta_count;
    req.data.tr069_req.data_size =  sizeof(int);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("tr069_getassocsta  failed \n");
    } else {
        printf(" %s:  TR069GETASSOCSTA VALUE:     %d \n",argv[1], *sta_count);
    }
    free(sta_count);
    close(s);
    return;
}

static void tr069_gettimestamp(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    struct timespec *time;
    char chanScanTime[40] = "\0";
    struct tm tm;
    struct timespec tstamp;
    struct timespec nowtime = {0};

    if (argc != 3) {
        usage_tr069_gettimestamp();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    time = (void *) malloc(sizeof( struct timespec));
    if(time == NULL) {
        printf("Insufficient memory");
        close(s);
        return;
    }
    memset(time, 0, sizeof(struct timespec));
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.param[0] = (int) time;
    req.data.tr069_req.cmdid = TR069_GETTIMESTAMP;
    req.data.tr069_req.data_addr = time;
    req.data.tr069_req.data_size = sizeof(struct timespec);

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("tr069_gettimestamp  failed \n");
        close(s);
        free(time);
        return;
    }
    clock_gettime(CLOCK_REALTIME, &nowtime);
    tstamp.tv_sec = nowtime.tv_sec - time->tv_sec;
    /*Convert timespec to date/time*/
    if(tspectotime(&tstamp, &tm, chanScanTime, sizeof(chanScanTime)) < 0)
        goto err;

    printf(" %s:  TR069ACSTIMESTAMP VALUE:     %s \n",argv[1], chanScanTime);

err:
    free(time);
    close(s);
    return;
}

static void tr069_getacsscan(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0,value;
    char *state = NULL;
    if (argc != 4) {
        usage_tr069_getacsscan();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    state  = (void *) malloc(TR69SCANSTATEVARIABLESIZE * sizeof (char));
    if(state == NULL) {
        printf("Insufficient memory");
        close(s);
        return;
    }
    memset(state, 0, TR69SCANSTATEVARIABLESIZE * sizeof(char));
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.param[3] = atoi(argv[3]);
    req.data.tr069_req.cmdid = TR069_GETDIAGNOSTICSTATE;
    req.data.tr069_req.data_addr = state;
    req.data.tr069_req.data_size = TR69SCANSTATEVARIABLESIZE * sizeof(char);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("TR069_getdiagnosticstate  failed \n");
    } else {
        printf(" %s:  TR069ACSDIAGNOSTICSTATE:     %s \n",argv[1], state);
    }

    free(state);
    close(s);
    return;
}

static void tr069_perstastatscount(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0,value;
    int *stats_count;
    if (argc != 3) {
        usage_tr069_perstastatscount();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    stats_count = (void *)malloc(sizeof(int));
    if(stats_count == NULL) {
        printf("Insufficient memory");
        close(s);
        return;
    }
    *stats_count = 0;
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GETNUMBEROFENTRIES;
    req.data.tr069_req.data_addr = stats_count;
    req.data.tr069_req.data_size =  sizeof(int);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("TR069_perstastatscount  failed \n");
    } else {
        printf(" %s:  TR069 PER STA STATS COUNT :     %d \n",argv[1], *stats_count);
    }
    free(stats_count);
    close(s);
    return;
}
static void tr069_get11hsupported(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0,value;
    int *supported;
    if (argc != 3) {
        usage_tr069_get11hsupported();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    supported = (void *)malloc(sizeof(int));
    if(supported == NULL) {
        printf("Insufficient memory");
        close(s);
        return;
    }
    *supported = 0;
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GET11HSUPPORTED;
    req.data.tr069_req.data_addr = supported;
    req.data.tr069_req.data_size =  sizeof(int);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("TR069_get11hsupported failed \n");
    } else {
        printf(" %s:  TR069GET11HSUPPORTED VALUE:     %d \n",argv[1], *supported);
    }
    free(supported);
    close(s);
    return;
}

static void tr069_getpowerrange(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0,i,value;
    ieee80211_tr069_txpower_range *range;
    if (argc != 3) {
        usage_tr069_getpowerrange();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    range =  (void *) malloc(sizeof(ieee80211_tr069_txpower_range));
    if(range == NULL) {
        printf("Insufficient memory");
        close(s);
        return;
    }
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GETPOWERRANGE;
    req.data.tr069_req.data_addr = range;
    req.data.tr069_req.data_size = sizeof(ieee80211_tr069_txpower_range);

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("TR069_getpowerrange failed \n");
        close(s);
        free(range);
        return;
    }
    if(range->value == -1){
        printf("This operation is not permitted when the Vap is up \n");
        free(range);
        close(s);
        return;
    }
    for(i = 0; i <= range->value; i++){
        printf(" %s:  TR069GETPOWERRANGE VALUE:     %d \n",argv[1], range->value_array[i]);
    }
    free(range);
    close(s);
    return;
}

static void tr069_chan_inuse(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    struct ieee80211_acs_dbg *acs = NULL;
    char buff[5] = "/0";
    char chanbuff[1024] = "/0"; /*max according to the spec*/

    if ((argc < 3) || (argc > 3))
    {
        usage_tr069_chan_inuse();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_GETACSREPORT;

    acs = (void *)malloc(sizeof(struct ieee80211_acs_dbg));

    if(NULL == acs) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    req.data.acs_rep.data_addr = acs;
    req.data.acs_rep.data_size = sizeof(struct ieee80211_acs_dbg);
    req.data.acs_rep.index = 0;
    acs->entry_id = 0;
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_GETACSREPORT failed");
        printf("error in ioctl \n");
        free(acs);
        close(s);
        return;
    }

    for (i = 0; i < acs->nchans; i++) {
        acs->entry_id = i;
        req.cmd = IEEE80211_DBGREQ_GETACSREPORT;
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            perror("DBG req failed");
            free(acs);
            close(s);
            return;
        }
        /*To make sure we are not getting more than 100 %*/
        if(acs->chan_load  > 100)
            acs->chan_load = 100;

        if(i == (acs->nchans - 1)) /*no comma at the end*/
            snprintf(buff, sizeof(buff), "%d", acs->ieee_chan);
        else
            snprintf(buff, sizeof(buff), "%d,", acs->ieee_chan);

        strlcat(chanbuff, buff, sizeof(chanbuff));
    }

    fprintf(stdout," List of Channels In Use \n");
    fprintf(stdout,"-------------------------\n");
    fprintf(stdout,"%s\n",chanbuff);

    free(acs);
    close(s);
    return;
}
    static void
tr069_getsupportedfrequency(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0,value;
    char *state = NULL;
    if (argc != 3) {
        usage_tr069_getsupportedfrequency();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    state  = (void *) malloc(15 * sizeof (char));
    if(state == NULL) {
        printf("insufficient memory");
        close(s);
        return;
    }
    memset(state, 0, 15 * sizeof(char));
    req.cmd = IEEE80211_DBGREQ_TR069;
    req.data.tr069_req.cmdid = TR069_GETSUPPORTEDFREQUENCY;
    req.data.tr069_req.data_addr = state;
    req.data.tr069_req.data_size = 15 * sizeof(char);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("tr069_getsupportedfreq  failed \n");
        free(state);
        close(s);
        return;
    }
    printf(" supported frequency is : %s \n",state);
    free(state);
    close(s);
    return;
}


static void tr069_set_oprate(const char *ifname, int argc, char *argv[])
{
#define MIN_PARAM  4
    struct iwreq iwr;
    int s, i;
    struct ieee80211req_athdbg req;
    u_int8_t *ratelist  = NULL ;

    if ((argc < MIN_PARAM)) {
        usage_tr069_setoprate();
        return;
    }

    ratelist  = argv[3] ;
    if (strlen(argv[3]) > 256)
        return;

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = ratelist;
    req.data.tr069_req.cmdid = TR069_SET_OPER_RATE;
    req.data.tr069_req.data_size = strlen(ratelist);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    close(s);
    return;
#undef MIN_PARAM

}

/*
 *  brief description
 *  Get the timestamp when the maximum number of stations
 *  has been associated from the driver and display it
 *
 */
static void assoc_dev_watermark_time(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int sock = 0;
    struct timespec *time;
    char assoc_watermarkTime[40] = "\0";
    struct tm assoc_tm;
    struct timespec tstamp;
    struct timespec nowtime = {0};

    if (argc != 3) {
        usage_assoc_dev_watermark_time();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return;
    }
    time = (void *) malloc(sizeof( struct timespec));
    if(time == NULL) {
        printf("Insufficient memory");
        return;
    }
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    req.cmd = IEEE80211_DBGREQ_ASSOC_WATERMARK_TIME;
    req.data.param[0] = (int) time;

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("assoc_dev_watermark_time failed \n");
        close(sock);
        free(time);
        return;
    }
    clock_gettime(CLOCK_REALTIME, &nowtime);
    tstamp.tv_sec = nowtime.tv_sec - time->tv_sec;
    /*Convert timespec to date/time*/
    if(tspectotime(&tstamp, &assoc_tm, assoc_watermarkTime, sizeof(assoc_watermarkTime)) < 0)
        goto err;

    printf(" %s:  ASSOC_WATERMARK_TIME VALUE:     %s \n",argv[1], assoc_watermarkTime);

err:
    free(time);
    close(sock);
    return;
}

/*
 * @set fw_test with arg and different value for fw testing in beeliner.
 * @param ifname : interface name
 * @param argc  : argument count
 * @param argv  : argument value
 *
 */

static void
beeliner_fw_test(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;

    if (argc < 5) {
        usage_beeliner_fw_test();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_FW_TEST;

        req.data.param[0] = strtoul(argv[3], NULL, 0);
        req.data.param[1] = strtoul(argv[4], NULL, 0);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBREQ failed");
        }
        close(s);
    }
    return;
}

/*
 * @set antenna switch dynamically.
 * @param ifname : interface name
 * @param argc  : argument count
 * @param argv  : argument value
 *
 */

static void
set_antenna_switch(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;

    if (argc < 5) {
        usage_set_antenna_switch();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_SET_ANTENNA_SWITCH;

        req.data.param[0] = atoi(argv[3]);
        req.data.param[1] = atoi(argv[4]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ , &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBGREQ  failed");
        }
        close(s);
    }
    return;
}


static void
init_rtt3(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    if ((argc < 5) || (argc > 5))
    {
        usage_init_rtt3();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_INITRTT3;

    req.dstmac[0] = 0x00;
    req.dstmac[1] = 0x00;
    req.dstmac[2] = 0x00;
    req.dstmac[3] = 0x00;
    req.dstmac[4] = 0x00;
    req.dstmac[5] = 0x00;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6))
    {
        errx(1, "Invalid mac address");
        return;
    }
    req.data.param[0] = atoi(argv[4]);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));


    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0)
    {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_RRMSTATSREQ failed");
    }
    close(s);

}
/*
 * @set chainmask per sta given the input macaddress and the nss value.
 *  Sets the txchainmask for the node with the given macaddress.
 * @param ifname : interface name
 * @param argc  : argument count
 * @param argv  : argument value
 *
 */

static void
chmask_per_sta(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len;
    struct ieee80211req_athdbg req;
    int chan_rptmode = 0;

    if (argc < 5) {
        usage_chmask_persta();
    }
    else {
        memset(&req, 0, sizeof(struct ieee80211req_athdbg));
        s = socket(AF_INET, SOCK_DGRAM, 0);
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        req.cmd = IEEE80211_DBGREQ_CHMASKPERSTA;

        if (!wifitool_mac_aton(argv[3], req.dstmac, 6)) {
            errx(1, "Invalid destination mac address");
            return;
        }
        req.data.param[0] = atoi(argv[4]);
        iwr.u.data.pointer = (void *) &req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
            errx(1, "IEEE80211_IOCTL_DBREQ failed");
        }
    }
    close(s);
    return;
}

static void tr069_get_oprate(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    char *ratelist = NULL;

    if ((argc < 3) || (argc > 3))
    {
        usage_tr069_getoprate();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    ratelist = (char *)malloc(256);

    if(NULL == ratelist) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    memset(ratelist, 0, 256);
    req.data.tr069_req.data_addr = ratelist;
    req.data.tr069_req.cmdid = TR069_GET_OPER_RATE;
    req.data.tr069_req.data_size = 256;

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        free(ratelist);
        close(s);
        return;
    }

    fprintf(stdout," List of Operationl Rates \n");
    fprintf(stdout,"-------------------------\n");
    fprintf(stdout,"%s\n",ratelist);

    free(ratelist);
    close(s);
    return;
}

static void tr069_get_posrate(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    char *ratelist = NULL;
    char buff[5] = "/0";

    if ((argc < 3) || (argc > 3))
    {
        usage_tr069_getposrate();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    ratelist = (char *)malloc(256);

    if(NULL == ratelist) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    memset(ratelist, 0, 256);
    req.data.tr069_req.data_addr = ratelist;
    req.data.tr069_req.cmdid = TR069_GET_POSIBLRATE;
    req.data.tr069_req.data_size = 256;

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        free(ratelist);
        close(s);
        return;
    }

    fprintf(stdout," List of Possible Rates \n");
    fprintf(stdout,"-------------------------\n");
    fprintf(stdout,"%s\n",ratelist);

    free(ratelist);
    close(s);
    return;
}

static void
tr069_set_bsrate(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, i;
    struct ieee80211req_athdbg req;
    u_int8_t *ratelist  = NULL ;

    if ((argc != 4)) {
        fprintf(stderr, "usage: wifitool athX tr069_set_bsrate value(s)");
        return;
    }

    ratelist = argv[3];
    if (strlen(argv[3]) > 256)
        return;

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = ratelist;
    req.data.tr069_req.cmdid = TR069_SET_BSRATE;
    req.data.tr069_req.data_size = strlen(ratelist);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    close(s);
    return;
}


static void
tr069_get_bsrate(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    char *ratelist = NULL;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_bsrate");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    ratelist = (char *)malloc(256);

    if(NULL == ratelist) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    memset(ratelist, 0, 256);
    req.data.tr069_req.data_addr = ratelist;
    req.data.tr069_req.cmdid = TR069_GET_BSRATE;
    req.data.tr069_req.data_size = 256;

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        free(ratelist);
        close(s);
        return;
    }

    fprintf(stdout," List of Basic Transmission Rates \n");
    fprintf(stdout,"-------------------------\n");
    fprintf(stdout,"%s\n",ratelist);

    free(ratelist);
    close(s);
    return;
}

static void
tr069_get_fail_retrans(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t failretrans = 0;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_fail_retrans");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &failretrans;
    req.data.tr069_req.cmdid = TR069_GET_FAIL_RETRANS_CNT;
    req.data.tr069_req.data_size = sizeof(failretrans);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Fail Retrasmit count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%d\n", failretrans);

    close(s);
    return;
}

static void
tr069_get_success_retrans(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t succretrans = 0;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_success_retrans");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &succretrans;
    req.data.tr069_req.cmdid = TR069_GET_RETRY_CNT;
    req.data.tr069_req.data_size = sizeof(succretrans);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Successful Retrasmit count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%u\n", succretrans);

    close(s);
    return;
}

static void
tr069_get_success_mul_retrans(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t succretrans = 0;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_success_retrans");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &succretrans;
    req.data.tr069_req.cmdid = TR069_GET_MUL_RETRY_CNT;
    req.data.tr069_req.data_size = sizeof(succretrans);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Successful Multiple Retrasmit count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%u\n", succretrans);

    close(s);
    return;
}

static void
tr069_get_ack_failures(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t ackfailures = 0;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_ack_failures");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &ackfailures;
    req.data.tr069_req.cmdid = TR069_GET_ACK_FAIL_CNT;
    req.data.tr069_req.data_size = sizeof(ackfailures);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," ACK Failures \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%d\n", ackfailures);

    close(s);
    return;
}

static void
tr069_get_retrans(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t retrans = 0;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_retrans");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &retrans;
    req.data.tr069_req.cmdid = TR069_GET_RETRANS_CNT;
    req.data.tr069_req.data_size = sizeof(retrans);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Retrasmit count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%d\n", retrans);

    close(s);
    return;
}

static void
tr069_get_aggr_pkts(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t aggrpkts = 0;

    if(argc != 3) {
        fprintf(stderr, "usage: wifitool athX tr069_get_aggr_pkts");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &aggrpkts;
    req.data.tr069_req.cmdid = TR069_GET_AGGR_PKT_CNT;
    req.data.tr069_req.data_size = sizeof(aggrpkts);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Aggregated packet count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%d\n", aggrpkts);

    close(s);
    return;
}

static void
tr069_get_sta_bytes_sent(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t bytessent = 0;

    if(argc != 4) {
        fprintf(stderr, "usage: wifitool athX tr069_get_sta_bytes_sent <STA MAC>");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        fprintf(stderr, "Invalid mac address");
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &bytessent;
    req.data.tr069_req.cmdid = TR069_GET_STA_BYTES_SENT;
    req.data.tr069_req.data_size = sizeof(bytessent);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Station bytes sent count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%d\n", bytessent);

    close(s);
    return;
}

static void
tr069_get_sta_bytes_rcvd(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s,i;
    struct ieee80211req_athdbg req;
    u_int32_t bytesrcvd = 0;

    if(argc != 4) {
        fprintf(stderr, "usage: wifitool athX tr069_get_sta_bytes_rcvd <STA MAC>");
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        fprintf(stderr, "Invalid mac address");
        close(s);
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_TR069;

    req.data.tr069_req.data_addr = &bytesrcvd;
    req.data.tr069_req.cmdid = TR069_GET_STA_BYTES_RCVD;
    req.data.tr069_req.data_size = sizeof(bytesrcvd);

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:IEEE80211_DBGREQ_TR069 failed");
        printf("error in ioctl \n");
        close(s);
        return;
    }

    fprintf(stdout," Station bytes received count \n");
    fprintf(stdout,"-----------------\n");
    fprintf(stdout,"%d\n", bytesrcvd);

    close(s);
    return;
}

static void
bsteer_setparams(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0, value;
    char *state = NULL;
    if (argc != 18) {
        usage_bsteer_setparams();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.bsteering_param.inactivity_timeout_normal = atoi(argv[3]);
    req.data.bsteering_param.inactivity_timeout_overload = atoi(argv[4]);
    req.data.bsteering_param.utilization_sample_period = atoi(argv[5]);
    req.data.bsteering_param.utilization_average_num_samples = atoi(argv[6]);
    req.data.bsteering_param.inactive_rssi_xing_high_threshold = atoi(argv[7]);
    req.data.bsteering_param.inactive_rssi_xing_low_threshold = atoi(argv[8]);
    req.data.bsteering_param.low_rssi_crossing_threshold = atoi(argv[9]);
    req.data.bsteering_param.inactivity_check_period = atoi(argv[10]);
    req.data.bsteering_param.low_tx_rate_crossing_threshold = atoi(argv[11]);
    req.data.bsteering_param.high_tx_rate_crossing_threshold = atoi(argv[12]);
    req.data.bsteering_param.low_rate_rssi_crossing_threshold = atoi(argv[13]);
    req.data.bsteering_param.high_rate_rssi_crossing_threshold = atoi(argv[14]);
    req.data.bsteering_param.ap_steer_rssi_xing_low_threshold = atoi(argv[15]);
    req.data.bsteering_param.interference_detection_enable = atoi(argv[16]);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_PARAMS;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_SET_PARAMS failed");
    }

    close(s);
    return;
}
static void
bsteer_getparams(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 3) {
        usage_bsteer_getparams();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_PARAMS;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_GET_PARAMS failed");
        close(s);
        return;
    }

    printf("Band steering parameters: \n");
    printf("-------------------------- ------------\n");
    printf("Normal inactivity timeout: %u s\n",
           req.data.bsteering_param.inactivity_timeout_normal);
    printf("Overload inactivity timeout: %u s\n",
           req.data.bsteering_param.inactivity_timeout_overload);
    printf("Utilization sampling period: %u s\n",
           req.data.bsteering_param.utilization_sample_period);
    printf("Utilization num samples to average: %u\n",
           req.data.bsteering_param.utilization_average_num_samples);
    printf("Inactive RSSI crossing high threshold: %u dB\n",
           req.data.bsteering_param.inactive_rssi_xing_high_threshold);
    printf("Inactive RSSI crossing low threshold: %u dB\n",
           req.data.bsteering_param.inactive_rssi_xing_low_threshold);
    printf("Low RSSI crossing threshold: %u dB\n",
           req.data.bsteering_param.low_rssi_crossing_threshold);
    printf("Inactivity check interval: %u s\n",
           req.data.bsteering_param.inactivity_check_period);
    printf("Active steeing low threshold: Tx rate %u Kbps, RSSI %u dB\n",
           req.data.bsteering_param.low_tx_rate_crossing_threshold,
           req.data.bsteering_param.low_rate_rssi_crossing_threshold);
    printf("Active steering high threshold: Tx rate %u Kbps, RSSI %u dB\n",
           req.data.bsteering_param.high_tx_rate_crossing_threshold,
           req.data.bsteering_param.high_rate_rssi_crossing_threshold);
    printf("AP steering low RSSI threshold: %u dB\n",
           req.data.bsteering_param.ap_steer_rssi_xing_low_threshold);
    printf("Interference detection enable: %u\n",
           req.data.bsteering_param.interference_detection_enable);

    close(s);
    return;
}

static void
bsteer_setdbgparams(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0, value;
    char *state = NULL;
    if (argc != 6) {
        usage_bsteer_setdbgparams();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.bsteering_dbg_param.raw_chan_util_log_enable = atoi(argv[3]);
    req.data.bsteering_dbg_param.raw_rssi_log_enable = atoi(argv[4]);
    req.data.bsteering_dbg_param.raw_tx_rate_log_enable = atoi(argv[5]);

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_DBG_PARAMS;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_SET_DBG_PARAMS failed");
    }

    close(s);
    return;
}

static void
bsteer_getdbgparams(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 3) {
        usage_bsteer_getdbgparams();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_DBG_PARAMS;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_GET_DBG_PARAMS failed");
        close(s);
        return;
    }

    printf("Band steering debug parameters: \n");
    printf("-------------------------- ------------\n");
    printf("Enable raw channel utilization logging: %s\n",
           req.data.bsteering_dbg_param.raw_chan_util_log_enable ?
           "yes" : "no");
    printf("Enable raw RSSI measurement logging: %s\n",
           req.data.bsteering_dbg_param.raw_rssi_log_enable ?
           "yes" : "no");

    close(s);
    return;
}

static void
bsteer_enable(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0, value;
    char *state = NULL;
    if (argc != 4) {
        usage_bsteer_enable();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.bsteering_enable = atoi(argv[3]);
    req.cmd = IEEE80211_DBGREQ_BSTEERING_ENABLE;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_ENABLE failed");
    }

    close(s);
    return;
}

static void
bsteer_enable_events(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0, value;
    char *state = NULL;
    if (argc != 4) {
        usage_bsteer_enable_events();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.bsteering_enable = atoi(argv[3]);
    req.cmd = IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS failed");
    }

    close(s);
    return;
}

static void
bsteer_setoverload(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0, value;
    char *state = NULL;
    if (argc != 4) {
        usage_bsteer_setoverload();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.bsteering_overload = atoi(argv[3]);
    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_OVERLOAD;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_SET_OVERLOAD failed");
    }

    close(s);
    return;
}

static void
bsteer_getoverload(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 3) {
        usage_bsteer_getoverload();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_OVERLOAD;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_GET_OVERLOAD failed");
        close(s);
        return;
    }

    printf("%s is %soverloaded\n", ifname,
           req.data.bsteering_overload ? "" : "not ");
    close(s);
}

static void
bsteer_getrssi(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 5) {
        usage_bsteer_getrssi();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_RSSI;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        errx(1, "Invalid mac address");
        return;
    }
    req.data.bsteering_rssi_num_samples = atoi(argv[4]);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("bsteer_getrssi");
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_GET_RSSI failed");
        close(s);
        return;
    }
    close(s);
}

static void
bsteer_setproberespwh(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 5) {
        usage_bsteer_setproberespwh();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
       errx(1, "Invalid mac address");
       return;
    }
    req.data.bsteering_probe_resp_wh = atoi(argv[4]);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("bsteer_setproberespwh");
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
                "IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH failed");
        close(s);
        return;
    }
    close(s);
}

static void
bsteer_getproberespwh(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 4) {
        usage_bsteer_getproberespwh();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_PROBE_RESP_WH;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        errx(1, "Invalid mac address");
        return;
    }
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
                "IEEE80211_DBGREQ_BSTEERING_GET_PROBE_RESP_WH failed");
        close(s);
        return;
    }

    printf("Probe responses withheld for %s on %s: %s\n", argv[3], ifname,
           req.data.bsteering_probe_resp_wh ? "yes" : "no");
    close(s);
}

static void
bsteer_setauthallow(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 5) {
        usage_bsteer_setauthallow();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_AUTH_ALLOW;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        errx(1, "Invalid mac address");
        return;
    }
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        errx(1, "Error in opening socket");
        return;
    }

    req.data.bsteering_auth_allow = atoi(argv[4]);
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        perror("bsteer_setauthallow");
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
                "IEEE80211_DBGREQ_BSTEERING_SET_AUTH_ALLOW failed");
    }
    close(s);
    return;
}

static void
bsteer_getdatarateinfo(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 4) {
        usage_bsteer_getdatarateinfo();
        return;
    }

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        errx(1, "Invalid mac address");
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
                "IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO failed");
        close(s);
        return;
    }

    printf("Data rate info for %s on %s: Static SMPS: %u, Max Bandwidth: %u, "
           "Num streams: %u, PHY mode: %u, Max MCS: %u, Max TX power: %u\n",
           argv[3], ifname, req.data.bsteering_datarate_info.is_static_smps,
           req.data.bsteering_datarate_info.max_chwidth,
           req.data.bsteering_datarate_info.num_streams,
           req.data.bsteering_datarate_info.phymode,
           req.data.bsteering_datarate_info.max_MCS,
           req.data.bsteering_datarate_info.max_txpower);
    close(s);
}

static void
bsteer_set_sta_stats_update_interval_da(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0;
    if (argc != 4) {
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_DA_STAT_INTVL;
    req.data.bsteering_sta_stats_update_interval_da = atoi(argv[3]);

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_SET_STEERING failed");
    }

    close(s);
    return;
}

static void
bsteer_setsteering(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr = { 0 };
    struct ieee80211req_athdbg req = { 0 };
    int s = 0, value;
    char *state = NULL;
    if (argc != 5) {
        usage_bsteer_setsteering();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_BSTEERING_SET_STEERING;
    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], MAC_ADDR_LEN)) {
        errx(1, "Invalid mac address");
        return;
    }
    req.data.bsteering_steering_in_progress = atoi(argv[4]);

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_BSTEERING_SET_STEERING failed");
    }

    close(s);
    return;
}
/*
wifitool athX custom_chan_list [-a 1-101 1-165] [-n 1-101 1-165]
  -a number of channels followed by IEEE number(s) of the channel(s)
     when sta is connected
  -n number of channels followed by IEEE number(s) of the channel(s)
     when sta is disconnected
     for ex: to fill channel 1 and 6 in associated list and 11 in non associated list
     wifitool athx custom_chan_list -a 2 1 6 -n 1 11
*/
static void custom_chan_list(const char *ifname, int argc, char *argv[])
{
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int sock;
    int i, j, x, y;
    int wait_event = 0;
    int ret;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("open:\n");
        return;
    }

    memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(sock);
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    iwr.u.data.pointer = (void *)&req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_CHAN_LIST;
    argc -= 3;
    i = 3;
    while (argc) {
        if (!strncmp(argv[i], "-a",2)) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 1 && x <= MAX_CUSTOM_CHANS) {
                argc--;
                i++;
                req.data.custom_chan_req.scan_numchan_associated = x;
                j = 0;
                while (x-- && argc) {
                    y = strtoul(argv[i], NULL, 10);
                    if (y >= 1 && y <= 165) {
                        argc--;
                        i++;
                        req.data.custom_chan_req.scan_channel_list_associated[j++] = y;
                    } else
                        break;
                }
                if (j != req.data.custom_chan_req.scan_numchan_associated)
                {
                    req.data.custom_chan_req.scan_numchan_associated = 0;
                    printf("USAGE: wifitool athX custom_chan_list -h ---for help\n");
                }
            }
            else {
                printf("Max supported channels is %d\n",MAX_CUSTOM_CHANS);
                printf("USAGE: wifitool athX custom_chan_list -h ---for help\n");
                close(sock);
                return;
            }
        }
        else if (!strncmp(argv[i], "-n",2)) {
            argc--;
            i++;
            if (!argc) {
                break;
            }
            x = strtoul(argv[i], NULL, 10);
            if (x >= 1 && x <= MAX_CUSTOM_CHANS) {
                argc--;
                i++;
                req.data.custom_chan_req.scan_numchan_nonassociated = x;
                j = 0;
                while (x-- && argc) {
                    y = strtoul(argv[i], NULL, 10);
                    if (y >= 1 && y <= 165) {
                        argc--;
                        i++;
                        req.data.custom_chan_req.scan_channel_list_nonassociated[j++] = y;
                    } else
                        break;
                }
                if (j != req.data.custom_chan_req.scan_numchan_nonassociated)
                {
                    req.data.custom_chan_req.scan_numchan_nonassociated = 0;
                    printf("USAGE: wifitool athX custom_chan_list -h ---for help\n");
                }
            }
            else {
                printf("Max supported channels is %d\n",MAX_CUSTOM_CHANS);
                printf("USAGE: wifitool athX custom_chan_list -h ---for help\n");
                close(sock);
                return;
            }
        }
        else if (!strncmp(argv[i], "-h",2)) {
            argc--;
            i++;
            printf("wifitool athX custom_chan_list [-a 1-101 1-165] [-n 1-101 1-165]\n");
            printf(" -a number of channels followed by IEEE number(s) of the channel(s) to scan when sta is connected\n");
            printf("-n :number of channels followed by IEEE number(s) of the channel(s) to scan when sta is not connected\n");
            printf("for ex: to fill channel 1 and 6 in associated list and 11 in non associated list\n");
            printf("wifitool athx custom_chan_list -a 2 1 6 -n 1 11\n");
            close(sock);
            return;

        }
        else {
            printf("USAGE: wifitool athX custom_chan_list -h ---for help\n");
            close(sock);
            return;

        }
    }
    ret = ioctl(sock, IEEE80211_IOCTL_DBGREQ, &iwr);
    if (ret < 0) {
        perror("ioctl:\n");
    }

    close(sock);

}
#if UMAC_SUPPORT_VI_DBG
/*
   wifitool athX vow_debug <stream_no> <marker_num> <marker_offset> <marker_match>
   wifitool athx vow_debug 1 2 0x00ffff 5
 */
static void vow_debug(const char *ifname, int argc, char *argv[])
{
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int s;
    int wait_event = 0;
    int ret;

    if (argc != 7) {
        usage_vow_debug();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.vow_dbg_stream_param.stream_num = atoi(argv[3]);
    req.data.vow_dbg_stream_param.marker_num = atoi(argv[4]);
    req.data.vow_dbg_stream_param.marker_offset = strtoul(argv[5], NULL, 16);
    req.data.vow_dbg_stream_param.marker_match = strtoul(argv[6], NULL, 16);
    req.cmd = IEEE80211_DBGREQ_VOW_DEBUG_PARAM_PERSTREAM;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
            "IEEE80211_DBGREQ_VOW_DEBUG_PARAMPERSTREAM failed");
    }

    close(s);
    return;
}

/*
   wifitool athX vow_debug_set_param <num of stream> <num of marker> <rxq offset> <rxq max> <time offset>
   wifitool athx vow_debug 1 1 0xffff0011 0xff112233 0xffffffff 0x12efde11
 */
static void vow_debug_set_param(const char *ifname, int argc, char *argv[])
{
    struct ieee80211req_athdbg req;
    struct iwreq iwr;
    int s;
    int wait_event = 0;
    int ret;

    if (argc != 9) {
        usage_vow_debug_set_param();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.data.vow_dbg_param.num_stream = atoi(argv[3]);
    req.data.vow_dbg_param.num_marker = atoi(argv[4]);
    req.data.vow_dbg_param.rxq_offset = strtoul(argv[5], NULL, 16);
    req.data.vow_dbg_param.rxq_shift = strtoul(argv[6], NULL, 16);
    req.data.vow_dbg_param.rxq_max = strtoul(argv[7], NULL, 16);
    req.data.vow_dbg_param.time_offset = strtoul(argv[8], NULL, 16);

    req.cmd = IEEE80211_DBGREQ_VOW_DEBUG_PARAM;
    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ:"
             "IEEE80211_DBGREQ_VOW_DEBUG_PARAM failed");
    }

    close(s);
    return;
}
#endif


#if QCA_NSS_PLATFORM
#define HOSTAPD_CONFIG_FILE_PREFIX "/var/run/hostapd"
#else
#define HOSTAPD_CONFIG_FILE_PREFIX "/tmp/sec"
#endif

static void
get_hostapd_param(const char *ifname, int argc, char *argv[])
{
    char fname[30];
    FILE *fp;
    char *pos;
    int  buflen = 0;
    char buf[80], param[40], val[64], fpar[40];

    if (argc != 4) {
        fprintf(stderr, "usage: wifitool athX get_hostapd_param param");
        return;
    }

    (void) memset(param, '\0', sizeof(param));
    (void) memset(val, '\0', sizeof(val));
    (void) memset(buf, '\0', sizeof(buf));

    if (strlcpy(param, argv[3], sizeof(param)) >= sizeof(param)) {
        printf("%s: param value too long %s\n", __func__, argv[3]);
        return;
    }
    buflen = sizeof(buf);

#if QCA_NSS_PLATFORM
    snprintf(fname, sizeof(fname), "%s-%s.conf", HOSTAPD_CONFIG_FILE_PREFIX, ifname);
#else
    snprintf(fname, sizeof(fname), "%s%s", HOSTAPD_CONFIG_FILE_PREFIX, ifname);
#endif

    if ((fp = fopen(fname, "r")) == NULL) {
        fprintf(stderr, "Unable to open file %s\n", fname);
        return;
    }
    while(fgets(buf, buflen, fp)) {
        (void) memset(fpar, '\0', sizeof(fpar));
        if((pos = strchr(buf, '=')) != NULL)
            strlcpy(fpar, buf, (pos - buf) * sizeof(char));
        if (strcmp(fpar, param) == 0) {
            pos++;
            printf("%s: %s\n", ifname, pos);
            fclose(fp);
            return;
        }
    }
    printf("%s: Parameter not found\n", ifname);
    fclose(fp);
    return;
}

static pid_t
find_pid(const char *process_name)
{
    pid_t pid = -1;
    glob_t pglob;
    char *procname, *buf;
    int buflen = strlen(process_name) + 1;
    unsigned tmp;

#if QCA_NSS_PLATFORM
    #define PROC_PATH "/proc/*/comm"
#else
    #define PROC_PATH "/proc/*/cmdline"
#endif

    /* Using glob function to list all the
     * processes names and their path using
     * pattern matching over /proc filesystem
     */
    if (glob(PROC_PATH, 0, NULL, &pglob) != 0)
        return pid;

    procname = malloc(buflen);
    if(procname == NULL) {
        goto proc_mem_fail;
    }
    memset(procname, '\0', buflen);
    strlcpy(procname, process_name, sizeof(procname));
    buf = malloc(buflen);
    if(buf == NULL) {
        goto buf_mem_fail;
    }

    for (tmp = 0; tmp < pglob.gl_pathc; ++tmp) {
        FILE *comm;

        if((comm = fopen(pglob.gl_pathv[tmp], "r")) == NULL)
            continue;
        if((fgets(buf, buflen, comm)) == NULL) {
            fclose(comm);
            continue;
        }
        fclose(comm);
        if(strstr(buf, procname) != NULL) {
            pid = (pid_t)atoi(pglob.gl_pathv[tmp] + strlen("/proc/"));
            break;
        }
    }

    free(buf);
buf_mem_fail:
    free(procname);
proc_mem_fail:
    globfree(&pglob);
    return pid;
#undef PROC_PATH
}

/* wifitool athX set_hostapd_param param value
 *
 * This command can be used to dynamically change a value in
 * the hostapd conf file by specifying the param exactly and
 * the value to be set
 *
 * A temporary file is created and all the previous paramters
 * and their values are copied here except the parameter to be
 * changed which gets the new value
 *
 * A SIGHUP is sent to the hostapd daemon and thus the changes
 * are effected through a daemon restart
 */

static void
set_hostapd_param(const char *ifname, int argc, char *argv[])
{
    char fname[40], tempfname[40];
    FILE *fp, *fp2;
    int buflen = 0, reslen = 0;
    char *pos;
    char buf[80], param[40], fpar[40], val[64], result[80];
    pid_t hostapd_pid;
    u_int8_t file_changed = 0;
    char hostapd_name[20]="hostapd";

    if (argc != 5) {
        fprintf(stderr, "usage: wifitool athX set_hostapd_param param value");
        return;
    }

    (void) memset(param, '\0', sizeof(param));
    (void) memset(buf, '\0', sizeof(buf));
    (void) memset(val, '\0', sizeof(val));
    (void) memset(result, '\0', sizeof(result));

    if (strlcpy(param, argv[3], sizeof(param)) >= sizeof(param)) {
        fprintf(stderr, "Param name too long %s\n", argv[3]);
        return;
    }

    if (strlcpy(val, argv[4], sizeof(val)) >= sizeof(val)) {
        fprintf(stderr, "Param value too long %s\n", argv[4]);
        return;
    }

    buflen = sizeof(buf);

#if QCA_NSS_PLATFORM
    snprintf(fname, sizeof(fname), "%s-%s.conf", HOSTAPD_CONFIG_FILE_PREFIX, ifname);
    snprintf(tempfname, sizeof(tempfname), "%s-%s.conf.temp", HOSTAPD_CONFIG_FILE_PREFIX, ifname);
#else
    snprintf(fname, sizeof(fname), "%s%s", HOSTAPD_CONFIG_FILE_PREFIX, ifname);
    snprintf(tempfname, sizeof(tempfname), "%s%s.temp", HOSTAPD_CONFIG_FILE_PREFIX, ifname);
#endif

    if ((fp = fopen(fname, "r")) == NULL) {
        fprintf(stderr, "Unable to open %s\n", fname);
        return;
    }
    if ((fp2 = fopen(tempfname, "w")) == NULL) {
        fprintf(stderr, "Unable to create a temp file %s\n", tempfname);
        fclose(fp);
        return;
    }
    rewind(fp);
    rewind(fp2);

    while (!feof(fp)) {
        if( fgets(buf, buflen, fp) == NULL )
            break;
        (void) memset(fpar, '\0', sizeof(fpar));
        if((pos = strchr(buf, '=')) != NULL)
            strlcpy(fpar, buf, ((pos - buf) * sizeof(char)));
        if( strcmp(fpar, param) == 0) {
            snprintf(result, sizeof(result), "%s=%s\n", param, val);
            fputs(result, fp2);
            file_changed=1;
            continue;
        }
        fputs(buf, fp2);
    }
    hostapd_pid = find_pid(hostapd_name);
    if(file_changed != 1 || hostapd_pid <= 0) {
        fprintf(stderr, "Parameter set error\n");
        remove(tempfname);
        goto clean_exit;
    }
    else {
        if(remove(fname) != 0) {
            fprintf(stderr, "Unable to remove %s\n", fname);
            goto clean_exit;
        }
        if(rename(tempfname, fname) != 0) {
            fprintf(stderr, "Unable to rename temp file %s to hostapd file %s\n", fname, tempfname);
            goto clean_exit;
        }
        kill(hostapd_pid, SIGHUP);
    }
clean_exit:
    fclose(fp);
    fclose(fp2);
    return;
}

/* maximum of 8 number digit it would read
 * the following numbers would be rejected
 *  - any numnber more than 8 digits
 *  - any number that looks like hex, but had non-hex in it
 *  - ignores all white spaces, ' ', '\t'
 *  - ignores all '\r', '\n'
 *  - empty file
 *  - return -1 as error or zero
 */

static int
get_number(FILE *fp, int hex, unsigned int *n, int *eol)
{
    int d=0;
    int i=0;
    char c=0;

    char t[9]={0};
    if (!n) return -1;
    if (!fp) return -1;
    for (; (c=fgetc(fp))!=EOF;)
        if ( (i == 0) && (c==' ' || c=='\t')) continue;
        else if ((i!=0) && (c==' ' || c=='\t' || c == '\r' || c == '\n'))
            break;
        else if (!isdigit(c)) return -1;
        else t[i++]=c;
    if (c==EOF && i==0) return -1;
    if (i>8) return -1;
    if (c=='\n') *eol=1;
    if(hex) {
        sscanf(t,"%x", &d);
    } else {
        sscanf(t,"%d", &d);
    }
    *n = d;
    return 0;
}

static inline unsigned char tohex(const unsigned char c)
{
    return ((c >= '0') && (c <= '9')) ? (c-'0') : (0xa+(c-'a'));
}

static int
get_xstream_2_xbytes(FILE *fp, u_int8_t *byte_stream, int len, int *eol)
{
    int i=0;
    int xi=0;
    char c=0;
    /* len is number of hex bytes, eg, len of ff is actually 1, it takes
     * two hex digits of length 4 bits each,
     * passed length is assumed to be number of bytes not number of nibbles
     */
    if (!byte_stream) return -1;
    if (len < 0) return -1;

    for (;((c=fgetc(fp))!=EOF)  ;)  {
        if (i==0 && (c==' ' || c=='\t')) continue;
        else if ((i!=0) && (c==' ' || c=='\t' || c=='\r' || c=='\n')) break;
        else if (!isxdigit(c)) return -1;
        else {
            if (!(i%2)) byte_stream[xi]=tohex(tolower((unsigned char)c));
            else {
                byte_stream[xi] = byte_stream[xi] << 4 | tohex(tolower((unsigned char)c));
                xi++;
            }
            i++;
        }
        if (i>len) return -1;
    }
    if (c=='\n') *eol=1;
    if (xi != len/2) return -1;
    return xi;
}

static int
ignore_extra_bytes(FILE *fp, int *eol)
{
    char c=0;
    /* flush out any thing buffered in stdout */
    fflush(stdout);
    fprintf(stderr, "\nIgnoring extra bytes at end\n");
    for (; (c=fgetc(fp))!= EOF;) {
        putc(c, stderr);
        fflush(stderr);
        if (c=='\n') { *eol=1; return 0;}
    }
    return -1;
}
enum {
    FIPS_SUCCESS=0,
    FIPS_INVALID_COMMAND=1,
    FIPS_INVALID_MODE=2,
    FIPS_INVALID_KEYLEN=3,
    FIPS_INVALID_DATALEN=4,
    FIPS_RANGE_CHECK_FAIL=5,
    FIPS_INVALID_KEY_MISMATCH=6,
    FIPS_INVALID_DATA_MISMATCH=7,
    FIPS_INVALID_EXPOP_MISMATCH=8,
    FIPS_MALLOC_FAIL=9,
    FIPS_TEST_FAIL=10,
};

char *fips_error[]={
    "fips_success",
    "fips_invalid_command",
    "fips_invalid_mode",
    "fips_invalid_keylen",
    "fips_invalid_datalen",
    "fips_range_check_fail",
    "fips_invalid_key_mismatch",
    "fips_invalid_data_mismatch",
    "fips_invalid_expop_mismatch",
    "fips_malloc_fail",
    "fips_test_fail"
};
int set_fips(const char *ifname, int argc, char *argv[])
{
    int sock_fd = 0, err, fips_fail = 0;
    int i, size, ret, cmd, keylen, datalen, mode;
    int en=0;
    struct iwreq iwr;
    struct ath_ioctl_fips *req=NULL;
    struct ath_fips_output *output_fips = NULL;
    u_int8_t *ptr = NULL;
    FILE *fp = NULL;
    u_int8_t key[32] = {0};
    u_int8_t data[1500] = {0};
    u_int8_t exp_op[1500] = {0};
    u_int8_t iv[16] = {0};

    int eol=0;
    struct ieee80211req_athdbg dbg;
    if(argc != 4) {
        printf("%s:%d\n Incorrect Usage!\n",__func__,__LINE__);
        usage();
    } else {
        fp = fopen (argv[3] , "r");
        if (fp == NULL) {
            printf("\n Unable to open given file %s\n", argv[3]);
            return -EFAULT;
        }
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        /* validate the file contents */
        while (ftell(fp) < size)
        {
            if (-1 == get_number(fp, 0, &cmd, &eol) || eol) {
                en=FIPS_INVALID_COMMAND;
                goto close_n_exit;
            }
            if (-1 == get_number(fp, 0, &mode, &eol) || eol) {
                en=FIPS_INVALID_MODE;
                goto close_n_exit;
            }
            if (-1 == get_number(fp, 0, &keylen, &eol) || eol) {
                en=FIPS_INVALID_KEYLEN;
                goto close_n_exit;
            }
            if (-1 == get_number(fp, 0, &datalen, &eol) || eol) {
                en=FIPS_INVALID_DATALEN;
                goto close_n_exit;
            }
            if ((cmd < 0) || (cmd > 1)  || (mode <0) || (mode > 1)||\
                    ((keylen != 16) && (keylen != 32)) ||\
                    ((datalen > 1488) ||\
                        (datalen < 16) || (datalen%16))) {
                en=FIPS_RANGE_CHECK_FAIL;
                goto close_n_exit;
            }

            if (keylen != get_xstream_2_xbytes(fp, key, keylen*2, &eol) || eol){
                en=FIPS_INVALID_KEY_MISMATCH;
                goto close_n_exit;
            }
            if (datalen != get_xstream_2_xbytes(fp, data, datalen*2, &eol) || eol){
                en=FIPS_INVALID_DATA_MISMATCH;
                goto close_n_exit;
            }
            /* there is possbility if IV not being present in the text file,
               so file ends with only expected output, just do not break after
               here, because we do not use IV any ways
             */
            if (datalen != get_xstream_2_xbytes(fp, exp_op, datalen*2, &eol)){
                en=FIPS_INVALID_EXPOP_MISMATCH;
                goto close_n_exit;
            }
            /* if IV is not present, do not break */
            if (!eol) {
                /* more likely IV is present, there could be a chance that there
                 * are few spaces and extra white spaces. That need to be ignored
                 */
                if (16 != get_xstream_2_xbytes(fp, iv, 16*2, &eol)){
                    if (eol) {
                        fprintf(stderr, "Invalid or no iv is present, ingoring for now \n");
                    }
                }
            } else {
                    memset(iv, 0, 16);
            }
            /* Allocating ath_ioctl_fips for sending to driver. Size would be dynamic based on input data length*/
            req = (struct ath_ioctl_fips *) malloc(sizeof(struct ath_ioctl_fips) + (datalen - sizeof(u_int32_t)));
            if (!req)  {
                en=FIPS_MALLOC_FAIL;
                goto close_n_exit;
            }
            req->fips_cmd = cmd;    /* 1 - encrypt/ 2 - decrypt*/
            req->key_len = keylen;  /* no of bytes*/
            req->data_len = datalen;/* no of bytes*/
            req->mode = mode;
            memcpy(req->key, key, req->key_len);
            memcpy(req->data, data, req->data_len);

            memcpy(req->iv, iv, 16);
            sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

            (void) memset(&iwr, '\0', sizeof(iwr));

            if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
                fprintf(stderr, "ifname too long: %s\n", ifname);
                goto close_n_exit;
            }
            dbg.cmd = IEEE80211_DBGREQ_FIPS;
            dbg.data.fips_req.data_addr = (void *) req;
            dbg.data.fips_req.data_size = sizeof(struct ath_ioctl_fips) +
                            (req->data_len - sizeof(u_int32_t));
            iwr.u.data.pointer = (void *) &dbg;
            iwr.u.data.length = sizeof(struct ieee80211req_athdbg);
            err = ioctl(sock_fd, IEEE80211_IOCTL_DBGREQ, &iwr);
            sleep (1);
            if (err < 0) {
                errx(1, "Unable to set fips");
                en=FIPS_TEST_FAIL;
                goto close_n_exit;
            }
            /* Read the output text from fips_req.data_addr */
            if (iwr.u.data.pointer != NULL) {
                output_fips = (struct ath_fips_output *)req;
                if (output_fips->error_status == 0) {
                    printf("\n Output Data Length:%d",
                            output_fips->data_len);
                    printf("\n Output Data from Crypto Engine\n");

                    ptr = (u_int8_t *) (output_fips->data);
                    for(i=0; i < output_fips->data_len; i++)
                    {
                        printf("%02x ",(*(ptr+i)));
                    }
                    if (memcmp(ptr, exp_op, output_fips->data_len) == 0)
                        fips_fail = 0;
                    else
                        fips_fail = 1;

                    printf("\n Expected Output \n");
                    for (i = 0; i < datalen; i++)
                        printf("%02x ", exp_op[i]);
                    if (fips_fail == 1)
                        printf("\n Known Answer Test Failed\n");
                    else
                        printf("\n Known Answer Test Passed\n");
                } else {
                    printf("\nOutput Error status from Firmware returned: %d\n",
                                output_fips->error_status);
                }
            }

            /* Freeing allocated ath_ioctl_fips data structure */
            if(req) {
                free(req);
                req=NULL;
            }
            /* ignore any junk in the line of the file, until we get \r\n */
            if(!eol) {
                ignore_extra_bytes(fp, &eol);
            }
            eol=0;
        }
        fclose(fp);
    }
    return 0;

close_n_exit:
    if(fp) fclose(fp);
    if(req) free(req);
    fflush(stdout);
    {
        int i=0;

        for (i=0; i<7;i++) fprintf(stderr, "%s\n", fips_error[i]);
    }
    fprintf(stderr, "Input Error: Plese fix them first error code :%s", fips_error[en]);
    fflush(stderr);
    if(sock_fd)
        close(sock_fd);
    return -1;
}


static void offchan_tx_test(const char *ifname, int argc, char *argv[])
{
#define MIN_OFFCHAN_PARAM_COUNT  5
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    ieee80211_offchan_tx_test_t *offchan_req;

    if ((argc != MIN_OFFCHAN_PARAM_COUNT)) {
        usage_offchan_tx_test();
        return;
    }

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    offchan_req = (ieee80211_offchan_tx_test_t *)&req.data.offchan_req;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s <= -1) {
        printf("Failed to create socket in %s \n",__func__);
        return;
    }

    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_OFFCHAN_TX;

    offchan_req->ieee_chan = atoi(argv[3]);
    offchan_req->dwell_time = atoi(argv[4]);

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "ieee80211_ioctl_dbgreq: IEEE80211_DBGREQ_OFFCHAN_TX failed");
        printf("error in ioctl \n");
    }

    close(s);
    return;
#undef MIN_OFFCHAN_PARAM_COUNT
}

static void set_innetwork_2g(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len,unicast=0;
    struct ieee80211req_athdbg req;
    ieee80211req_rrmstats_t *rrmstats_req;
    ieee80211_rrmstats_t *rrmstats = NULL;

    if ((argc < 3) || (argc > 5)) {
        usage_set_innetwork_2g();
        return;
    }
    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }

    req.cmd = IEEE80211_DBGREQ_SETINNETWORK_2G;

    if (!wifitool_mac_aton(argv[3], &req.dstmac[0], 6)) {
        errx(1, "Invalid mac address");
        return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.data.param[0] =  atoi(argv[4]);
    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_SETINNETWORK_2G failed");
    }

    return ;


}

static void get_innetwork_2g(const char *ifname, int argc, char *argv[])
{
    struct iwreq iwr;
    int s, len,i;
    struct ieee80211req_athdbg req;
    struct in_network_2G_table *table_2g = NULL;

    if ((argc < 3) || (argc > 3))
    {
        usage_get_innetwork_2g();
        return;
    }

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));
    s = socket(AF_INET, SOCK_DGRAM, 0);
    (void) memset(&iwr, 0, sizeof(iwr));

    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
       fprintf(stderr, "ifname too long: %s\n", ifname);
       close(s);
       return;
    }

    iwr.u.data.pointer = (void *) &req;
    iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
    req.cmd = IEEE80211_DBGREQ_GETINNETWORK_2G;

    table_2g = (void *)malloc(sizeof(struct in_network_2G_table));

    if(NULL == table_2g) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    req.data.acs_rep.data_addr = table_2g;
    req.data.acs_rep.data_size = sizeof(struct in_network_2G_table);
    req.data.acs_rep.index = 0;
    table_2g->total_index = 0;

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        free(table_2g);
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_GETINNETWORK_2G failed");
        printf("error in ioctl \n");
        return;
    }
    len = table_2g->total_index;
    free(table_2g);
    table_2g = (void *)malloc(len*sizeof(struct in_network_2G_table));

    (void) memset(table_2g, 0, len*sizeof(struct in_network_2G_table));

    if(NULL == table_2g) {
        printf("insufficient memory \n");
        close(s);
        return;
    }
    req.data.acs_rep.data_addr = table_2g;
    req.data.acs_rep.data_size = sizeof(struct in_network_2G_table)*len;
    req.data.acs_rep.index = 1;
    table_2g->total_index = len;

    if (ioctl(s, IEEE80211_IOCTL_DBGREQ, &iwr) < 0) {
        free(table_2g);
        close(s);
        errx(1, "IEEE80211_IOCTL_DBGREQ: IEEE80211_DBGREQ_GETINNETWORK_2G failed");
        printf("error in ioctl \n");
        return;
    }
    if (table_2g->total_index!=0)
    {
        fprintf(stdout,"STA MAC  STA CH\n");
        fprintf(stdout,"-------------------------\n");
        for (i=0;i<table_2g->total_index;i++)
        {

            fprintf(stdout,"%2x:%2x:%2x:%2x:%2x:%2x  %d\n",table_2g[i].macaddr[0],table_2g[i].macaddr[1],table_2g[i].macaddr[2],
                table_2g[i].macaddr[3],table_2g[i].macaddr[4],table_2g[i].macaddr[5],table_2g[i].ch);
        }
    }
    else
        fprintf(stdout,"no data\n");
    close(s);
    free(table_2g);
    return;
}
    int
main(int argc, char *argv[])
{
    const char *ifname, *cmd;

	if (argc < 3)
	{
		printf("%s:%d",__func__,__LINE__);
		usage();
	}

    ifname = argv[1];
    cmd = argv[2];
    if (streq(cmd, "fips")){
        set_fips(ifname, argc, argv);
    }
    else if (streq(cmd, "sendaddba")) {
        send_addba(ifname, argc, argv);
    } else if (streq(cmd, "senddelba")) {
        send_delba(ifname, argc, argv);
    } else if (streq(cmd, "setaddbaresp")) {
        set_addbaresp(ifname, argc, argv);
    } else if (streq(cmd, "sendsingleamsdu")) {
        send_singleamsdu(ifname, argc, argv);
    } else if (streq(cmd, "getaddbastats")) {
        get_addbastats(ifname, argc, argv);
    } else if (streq(cmd, "sendbcnrpt")) {
        send_bcnrpt(ifname, argc, argv);
    } else if (streq(cmd, "sendtsmrpt")) {
        send_tsmrpt(ifname, argc, argv);
    } else if (streq(cmd, "sendneigrpt")) {
        send_neigrpt(ifname, argc, argv);
    } else if (streq(cmd, "sendlmreq")) {
        send_lmreq(ifname, argc, argv);
    } else if (streq(cmd, "sendbstmreq")) {
        send_bstmreq(ifname, argc, argv);
    } else if (streq(cmd, "sendbstmreq_target")) {
        send_bstmreq_target(ifname, argc, argv);
    } else if (streq(cmd, "setbssidpref")) {
        set_bssidpref(ifname, argc, argv);
    } else if (streq(cmd, "senddelts")) {
        send_delts(ifname, argc, argv);
    } else if (streq(cmd, "sendaddts")) {
        send_addts(ifname, argc, argv);
    } else if (streq(cmd, "sendchload")) {
        send_chload(ifname, argc, argv);
    } else if (streq(cmd, "sendnhist")) {
        send_noisehistogram(ifname,argc,argv);
    } else if (streq(cmd, "sendstastats")) {
        send_stastats(ifname, argc, argv);
    } else if (streq(cmd, "sendlcireq")) {
        send_lcireq(ifname, argc, argv);
    } else if (streq(cmd, "rrmstats")) {
        get_rrmstats(ifname, argc, argv);
    } else if (streq(cmd, "sendfrmreq")) {
        send_frmreq(ifname, argc, argv);
    } else if (streq(cmd, "bcnrpt")) {
        get_bcnrpt(ifname, argc, argv);
    } else if (streq(cmd, "getrssi")) {
        get_rssi(ifname, argc, argv);
    } else if (streq(cmd, "acsreport")) {
        acs_report(ifname, argc, argv);
    } else if (streq(cmd, "setchanlist")) {
        channel_loading_channel_list_set(ifname, argc, argv);
    } else if (streq(cmd, "getchanlist")) {
        channel_loading_channel_list_get(ifname, argc, argv);
    } else if (streq(cmd, "block_acs_channel")) {
        block_acs_channel(ifname, argc, argv);
    } else if (streq(cmd, "tr069_chanhist")) {
        tr069_chan_history(ifname, argc, argv);
    } else if (streq(cmd, "get_assoc_time")) {
        get_assoc_time(ifname, argc, argv);
    } else if (streq(cmd, "tr069_txpower")) {
        tr069_txpower(ifname, argc, argv);
    } else if (streq(cmd, "tr069_gettxpower")) {
        tr069_gettxpower(ifname, argc, argv);
    } else if (streq(cmd, "tr069_guardintv")) {
        tr069_guardintv(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_guardintv")) {
        tr069_get_guardintv(ifname, argc, argv);
    } else if (streq(cmd, "tr069_getassocsta")) {
        tr069_getassocsta(ifname, argc, argv);
    } else if (streq(cmd, "tr069_getacstimestamp")) {
        tr069_gettimestamp(ifname, argc, argv);
    } else if (streq(cmd, "tr069_getacsscan")) {
        tr069_getacsscan(ifname, argc, argv);
    } else if (streq(cmd, "tr069_persta_statscount")) {
        tr069_perstastatscount(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_11hsupported")) {
        tr069_get11hsupported(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_powerrange")) {
        tr069_getpowerrange(ifname, argc, argv);
    } else if (streq(cmd, "tr069_chan_inuse")) {
        tr069_chan_inuse(ifname, argc, argv);
    } else if (streq(cmd, "tr069_set_oprate")) {
        tr069_set_oprate(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_oprate")) {
        tr069_get_oprate(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_posrate")) {
        tr069_get_posrate(ifname, argc, argv);
    } else if (streq(cmd, "tr069_set_bsrate")) {
        tr069_set_bsrate(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_bsrate")) {
        tr069_get_bsrate(ifname, argc, argv);
    } else if (streq(cmd, "get_hostapd_param")) {
        get_hostapd_param(ifname, argc, argv);
    } else if (streq(cmd, "set_hostapd_param")) {
        set_hostapd_param(ifname, argc, argv);
    } else if (streq(cmd, "supported_freq")) {
        tr069_getsupportedfrequency(ifname,argc,argv);
    } else if (streq(cmd, "chmask_persta")) {
        chmask_per_sta(ifname, argc, argv);
    } else if (streq(cmd, "beeliner_fw_test")) {
        beeliner_fw_test(ifname, argc, argv);
    } else if (streq(cmd, "init_rtt3")) {
        init_rtt3(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_getparams")) {
        bsteer_getparams(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_setparams")) {
        bsteer_setparams(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_getdbgparams")) {
        bsteer_getdbgparams(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_setdbgparams")) {
        bsteer_setdbgparams(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_enable")) {
        bsteer_enable(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_enable_events")) {
        bsteer_enable_events(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_setoverload")) {
        bsteer_setoverload(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_getoverload")) {
        bsteer_getoverload(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_getrssi")) {
        bsteer_getrssi(ifname, argc, argv);
    }  else if (streq(cmd, "bsteer_setproberespwh")) {
        bsteer_setproberespwh(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_getproberespwh")) {
        bsteer_getproberespwh(ifname, argc, argv);
    }  else if (streq(cmd, "bsteer_setauthallow")) {
        bsteer_setauthallow(ifname, argc, argv);
    } else if (streq(cmd, "set_antenna_switch")) {
        set_antenna_switch(ifname, argc, argv);
    } else if (streq(cmd, "set_usr_ctrl_tbl")) {
        set_usr_ctrl_tbl(ifname, argc, argv);
    } else if (streq(cmd, "offchan_tx_test")) {
        offchan_tx_test(ifname, argc, argv);
    } else if (streq(cmd, "rrm_sta_list")) {
        rrm_sta_list(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_getdatarateinfo")) {
        bsteer_getdatarateinfo(ifname, argc, argv);
    } else if (streq(cmd, "mu_scan")) {
        mu_scan(ifname, argc, argv);
    } else if (streq(cmd, "lteu_cfg")) {
        lteu_cfg(ifname, argc, argv);
    } else if (streq(cmd, "ap_scan")) {
        ap_scan(ifname, argc, argv);
    } else if (streq(cmd, "rpt_prb_time")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_rpt_prb_time")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "rest_time")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_rest_time")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "idle_time")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_idle_time")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "prb_delay")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_prb_delay")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "mu_delay")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_mu_delay")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "sta_tx_pow")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_sta_tx_pow")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "prb_spc_int")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "g_prb_spc_int")) {
        lteu_param(ifname, argc, argv);
    } else if (streq(cmd, "atf_debug_size")) {
        atf_debug_size(ifname, argc, argv);
    } else if (streq(cmd, "atf_dump_debug")) {
        atf_dump_debug(ifname, argc, argv);
    } else if (streq(cmd, "atf_debug_nodestate")) {
        atf_debug_nodestate(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_vap_stats")) {
        tr069_get_aggr_pkts(ifname, argc, argv);
        tr069_get_retrans(ifname, argc, argv);
        tr069_get_success_retrans(ifname, argc, argv);
        tr069_get_success_mul_retrans(ifname, argc, argv);
        tr069_get_ack_failures(ifname, argc, argv);
        tr069_get_fail_retrans(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_fail_retrans")) {
        tr069_get_fail_retrans(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_success_retrans")) {
        tr069_get_success_retrans(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_success_mul_retrans")) {
        tr069_get_success_mul_retrans(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_ack_failures")) {
        tr069_get_ack_failures(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_retrans")) {
        tr069_get_retrans(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_aggr_pkts")) {
        tr069_get_aggr_pkts(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_sta_stats")) {
        tr069_get_sta_bytes_sent(ifname, argc, argv);
        tr069_get_sta_bytes_rcvd(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_sta_bytes_sent")) {
        tr069_get_sta_bytes_sent(ifname, argc, argv);
    } else if (streq(cmd, "tr069_get_sta_bytes_rcvd")) {
        tr069_get_sta_bytes_rcvd(ifname, argc, argv);
    } else if (streq(cmd, "bsteer_setsteering")) {
        bsteer_setsteering(ifname, argc, argv);
    } else if (streq(cmd, "custom_chan_list")) {
       custom_chan_list(ifname, argc, argv) ;
#if UMAC_SUPPORT_VI_DBG       
    } else if (streq(cmd, "vow_debug_set_param")) {
	    vow_debug_set_param(ifname, argc, argv);
    } else if (streq(cmd,"vow_debug")) {
	    vow_debug(ifname, argc, argv);
#endif	    
    } else if (streq(cmd, "display_traffic_statistics")) {
        display_traffic_statistics(ifname, argc, argv) ;
    }else if (streq(cmd, "get_assoc_dev_watermark_time")) {
            assoc_dev_watermark_time(ifname, argc, argv);
    } else if (streq(cmd, "set_innetwork_2g")) {
        set_innetwork_2g(ifname, argc, argv);
    } else if (streq(cmd, "get_innetwork_2g")) {
        get_innetwork_2g(ifname, argc, argv);
    } else {
        usage();
    }
    return 0;
}
