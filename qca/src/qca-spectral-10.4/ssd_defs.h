/*
 * =====================================================================================
 *
 *       Filename:  ssd_defs.h
 *
 *    Description:  Spectral Scan Defines
 *
 *        Version:  1.0
 *        Created:  11/21/2011 11:27:10 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012 Qualcomm Atheros, Inc.
 *        All Rights Reserved
 *        Qualcomm Atheros Confidential and Proprietary
 *
 * =====================================================================================
 */


#ifndef _SSD_DEFS_H_
#define _SSD_DEFS_H_


#include <sys/ioctl.h>
#include <sys/select.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <math.h>
#include "spectral_data.h"
#include "spec_msg_proto.h"
#include "classifier.h"

#define ATHPORT 8001    /* port users will be connecting to */
#define BACKLOG 10      /* number of pending connections queue will hold */


#define CHANNEL_01_FREQ  2412
#define CHANNEL_02_FREQ  2417
#define CHANNEL_03_FREQ  2422
#define CHANNEL_04_FREQ  2427
#define CHANNEL_05_FREQ  2432
#define CHANNEL_06_FREQ  2437
#define CHANNEL_07_FREQ  2442
#define CHANNEL_08_FREQ  2447
#define CHANNEL_09_FREQ  2452
#define CHANNEL_10_FREQ  2457
#define CHANNEL_11_FREQ  2462
#define CHANNEL_12_FREQ  2467
#define CHANNEL_13_FREQ  2472
#define CHANNEL_14_FREQ  2482

#define CHANNEL_NUM_05      5
#define CHANNEL_NUM_13      13


#define SSD_ALARAM_VAL      1
#define SSD_USEC_ALARM_VAL  200000
#define DEFAULT_MAXHOLD_INT 5000
#define DEFAULT_MINPOWER    -100
#define BIN_POWER_COUNT     128

#define ENABLE_CLASSIFIER_PRINT 1

#define TRUE    (1)
#define FALSE   !(TRUE)


#define streq(a, b)     ((strcasecmp((a), (b)) == 0))
#define here()          printf("%s : %d\n", __func__, __LINE__)
#define not_yet()       printf("TODO : %s : %d\n", __func__, __LINE__)

#ifndef NETLINK_GENERIC
    #define NETLINK_GENERIC 16
#endif  /* NETLINK_GENERIC */


#define MAX_PAYLOAD                 1024
#define MAX_SAVED_SAMP_MESSAGES     10
#define GUI_UPPER_FREQ              2472
#define GUI_LOWER_FREQ              2432
#define GUI_IGNORE_THIS_BIN_VALUE   255
#define CMD_BUF_SIZE                256
#define SAMPLE_COUNT                128
#define DEFAULT_MAX_RSSI            -120
#define MAX_INTERF_COUNT            10

/*
 * ssd : various operational state 
 */

typedef enum ssd_state {
    IDLE = 0,
    CONNECTED_TO_GUI,
    SCAN_INIT,
    SCANNING,
    SCAN_COMPLETE,
    ERROR,
}ssd_state_t;

#define set_state(p, val)   (p->state = val)
#define get_state(p)        (p->state)

typedef struct ssd_config {
    int eacs;
    int current_freq;
    int prev_freq;
    int minpower;
    int change_freq;
    int change_channel;
    int raw_fft;
    int scale;
    int use_rssi;
    int flip;
    int index_data;
    int rssi_only;
    int classify;
    int power_per_bin;
    int maxhold_interval;
    int atheros_ui;
}ssd_config_t;

typedef struct ssd_stats {
    int channel_switch;
    int alarm;
}ssd_stats_t;

#define set_config(p, elem, val)    (p->elem = val)
#define get_config(p, elem)         (p->elem)

typedef struct ssd_samp_info {
    SPECTRAL_SAMP_MSG lower_max_rssi_msg;
    SPECTRAL_SAMP_MSG upper_max_rssi_msg;
    int16_t lower_maxrssi;
    int16_t upper_maxrssi;
    int32_t lower_last_tstamp;
    int32_t upper_last_tstamp;
    int num_samp_saved;
    int num_samp_sent;
    int num_samp_to_save;
    int total_channel_switches;
    int num_resp_reqd;
}ssd_samp_info_t;

#define SSD_LIST_FULL    1
#define SSD_LIST_EMPTY   2
#define SSD_LIST_ERROR   3
#define SSD_LIST_OK      4

typedef struct ssd_buffer {
    int length;
    int valid;
    SPECTRAL_SAMP_MSG msg;
}ssd_buffer_t;

typedef struct ssd_samp_msg_buffers {
    int read_index;
    int write_index;
    int count;
    int prev_index;
    int freq;
    ssd_buffer_t buf[MAX_SAVED_SAMP_MESSAGES];
}ssd_samp_msg_buffers_t;

/*
 * Main spectral scan daemon information structure
 */

typedef struct ssd_info {

    SPECTRAL_SAMP_MSG           silent_msg;

    int prev_saved_index;

    int send_single;
    int num_saved;
    int num_sent;
    int num_to_save;
    int sock_fd;

    /* netlink socket details */
    struct sockaddr_nl src_addr;
    struct sockaddr_nl dst_addr;
    struct nlmsghdr    *nlh;
    struct msghdr      msg;
    struct iovec       iov;

    ssd_config_t    config;     /* configuration */
    ssd_state_t     state;      /* state info   */

    ssd_stats_t     stats;
    ssd_samp_info_t sampinfo;   /* SAMP info */
    ssd_samp_msg_buffers_t lower_msg_pool;
    ssd_samp_msg_buffers_t upper_msg_pool;

    /* classifier related data structures */
    struct ss lwrband;
    struct ss uprband;

    /* interference related */
    struct INTERF_RSP interf_rsp[MAX_INTERF_COUNT];
    int interf_count;

    /* Track channel sweep state */
    int channel_sweeped;
}ssd_info_t;

#define GET_SAMP_INFO_PTR(p)        (&p->sampinfo)
#define GET_STATS_PTR(p)            (&p->stats)
#define GET_CONFIG_PTR(p)           (&p->config)
#define GET_SILENT_SAMP_MSG_PTR(p)  (&p->silent_msg)

/* ssd info */
extern ssd_info_t ssd;


extern SPECTRAL_SAMP_MSG    lower_max_rssi_msg;
extern SPECTRAL_SAMP_MSG    upper_max_rssi_msg;
extern struct INTERF_RSP    interference_rsp[MAX_INTERF_COUNT];
extern int16_t  lower_max_rssi;
extern int16_t  upper_max_rssi;
extern int32_t  lower_last_tstamp;
extern int32_t  upper_last_tstamp;


/* function prototypes */

extern int put_msg(ssd_info_t *pinfo, char *data, int len, ssd_samp_msg_buffers_t *p);
extern int get_msg(ssd_info_t *pinfo, int *index, ssd_samp_msg_buffers_t *p);
extern int ssd_init_ssd_samp_msg_buffers(ssd_info_t *pinfo);

#endif  // _SSD_DEFS_H_
