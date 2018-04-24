/*
* Copyright (c) 2016 Qualcomm Atheros, Inc.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

/*
 * QCA specific tool to trigger channel swicth and scan.
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>
#include <unistd.h>
#include <stdint.h>

#include "if_athioctl.h"
#include <ext_ioctl_drv_if.h>

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN 1234  /* LSB first: i386, vax */
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321/* MSB first: 68000, ibm, net */
#endif
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#define FALSE   0
#define TRUE    1
#define MAX_INTERFACE_NAME_LEN    20
#define BASE10  10
#define INVALID_ARG  (-1)
/**
* @brief    Prints usage message.
*/
static void print_usage() {
    /* print usage message */
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "1: exttool --chanswitch"
            " --interface wifiX"
            " --chan <dest primary channel>"
            " --chwidth <channelwidth>"
            " --numcsa <channel switch announcement count>"
            " --secoffset <1: PLUS, 3: MINUS> "
            " --cfreq2 <secondary 80 centre channel freq,"
            " applicable only for 80+80 MHz>\n");

     fprintf(stdout, "2: exttool --scan"
            " --interface wifiX"
            " --mindwell <min dwell time> allowed range [50ms to less than <max dwell>]"
            " --maxdwell <max dwell time> allowed range [greater than min dwell to 10000ms]"
            " --resttime <rest time > allowed ranged [greater than 0]"
            " --scanmode <1: ACTIVE, 2: PASSIVE> "
            " --chcount < Channel count and chan number > [ chancount <1 to 32>]\n");

    fprintf(stdout, "3: exttool --rptrmove"
            " --interface wifiX"
            " --chan <target root AP channel>"
            " --ssid <SSID of target Root AP> "
            " --bssid <BSSID of target Root AP> "
            " --numcsa <channel switch announcement count>"
            " --cfreq2 <secondary 80 centre channel freq,"
            " applicable only for 80+80 MHz>\n");
}


#define MIN_DWELL_TIME        200  /* DEFAULT MIN DWELL Time for scanning 20ms */
#define MAX_DWELL_TIME        300  /* default MAX_DWELL time for scanning 300 ms */
#define CHAN_MIN                1  /* Lowest number channel */
#define CHAN_MAX              165  /* highest number channel */
#define PASSIVE_SCAN		0x0001  /* scan mode is passive*/
#define ACTIVE_SCAN		0x0002  /* scan mode is active*/

int validate_scan_param( wifi_scan_custom_request_cmd_t *scan_req)
{
    if ((scan_req->min_dwell_time <= 0)) {
        fprintf(stdout, "Invalid min dwell time \n");
        return INVALID_ARG;
    }

    if ((scan_req->max_dwell_time <= 0)) {
        fprintf(stdout, "Invalid max dwell time \n");
        return INVALID_ARG;
    }

    if (scan_req->rest_time <= 0) {
        fprintf(stdout, "Invalid rest time \n");
        return INVALID_ARG;
    }

    if ((scan_req->scan_mode != PASSIVE_SCAN) &&
        (scan_req->scan_mode != ACTIVE_SCAN)) {
        fprintf(stdout, "Invalid scan mode: %d, it should be 1-Passive/2-Active\n", scan_req->scan_mode);
        return INVALID_ARG;
    }
    if ((scan_req->chanlist.n_chan <= 0) ||
        (scan_req->chanlist.n_chan > 32)) {
        fprintf(stdout, "Invalid number of channels requested to scan \n");
        return INVALID_ARG;
    }
    return 0;
}

int
main(int argc, char *argv[])
{

    wifi_channel_switch_request_t channel_switch_req;
    wifi_scan_custom_request_cmd_t channel_scan_req;
    wifi_repeater_move_request_t repeater_move_req;
    struct extended_ioctl_wrapper extended_cmd;
    char ifname[MAX_INTERFACE_NAME_LEN] = {'\0', };
    struct ifreq ifr;
    unsigned int subioctl_cmd = EXTENDED_SUBIOCTL_INVALID;
    int s = -1;
    int option = -1;
    int index = -1;
    int count = 0;
    int i = 0;
    char *cmd = NULL;
    int bssid[BSSID_LEN];

    static struct option exttool_long_options[] = {
        /* List of options supported by this tool */
        {"help",          no_argument,       NULL, 'h'},
        {"interface",     required_argument, NULL, 'i'},
        {"chanswitch",    no_argument,       NULL, 'c'},
        {"scan",          no_argument,       NULL, 's'},
        {"chan",          required_argument, NULL, 'a'},
        {"chwidth",       required_argument, NULL, 'w'},
        {"numcsa",        required_argument, NULL, 'n'},
        {"secoffset",     required_argument, NULL, 'o'},
        {"cfreq2",        required_argument, NULL, 'f'},
        {"mindwell",      required_argument, NULL, 'd'},
        {"maxdwell",      required_argument, NULL, 'x'},
        {"resttime",      required_argument, NULL, 'r'},
        {"scanmode",      required_argument, NULL, 'm'},
        {"chcount",       required_argument, NULL, 'e'},
        {"rptrmove",      no_argument,       NULL, 'p'},
	{"ssid",          required_argument, NULL, 'q'},
	{"bssid",         required_argument, NULL, 'b'},
        {0,               0,                 0,     0},
    };

    if (argc < 6) {
        print_usage();
        return -1;
    }

    memset(&channel_switch_req, 0, sizeof(channel_switch_req));
    memset(&channel_scan_req, 0, sizeof(wifi_scan_custom_request_cmd_t));
    memset(&repeater_move_req, 0, sizeof(wifi_repeater_move_request_t));

    /* Set channel width by default to MAX. Incase channel switch is triggered
     * with no channel width information provided, we use the channel width
     * of the current operating channel
     */
    channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_MAX_ELEM;

    while (TRUE)
    {
        option = getopt_long (argc, argv, "hi:csa:w:n:o:f:d:x:r:m:e:pq:b:",
                exttool_long_options, &index);

        if (option == -1) {
            break;
        }

        switch (option) {
            case 'h': /* Help */
                print_usage();
                break;
            case 'i': /* Interface name */
                if (strlcpy(ifname, optarg, MAX_INTERFACE_NAME_LEN) >= MAX_INTERFACE_NAME_LEN) {
                    printf("interface name too long");
                    return -1;
                }
                if (strncmp(ifname, "wifi", 4) != 0) {
                    fprintf(stdout, "Invalid interface name %s \n", ifname);
                    print_usage();
                    return -1;
                }
                break;
            case 'c': /* Channel switch request */
                subioctl_cmd = EXTENDED_SUBIOCTL_CHANNEL_SWITCH;
                break;
            case 's': /* Channel scan request */
                subioctl_cmd = EXTENDED_SUBIOCTL_CHANNEL_SCAN;
                break;
            case 'p': /* Repeater move request */
                subioctl_cmd = EXTENDED_SUBIOCTL_REPEATER_MOVE;
                break;
            case 'w': /* New channel width */
                channel_switch_req.target_chanwidth = atoi(optarg);
                break;
            case 'a': /* New primary 20 centre channel number */
                channel_switch_req.target_pchannel = atoi(optarg);
                break;
            case 'f': /* New secondary 80 MHz channel centre frequency for 80+80 */
                channel_switch_req.target_cfreq2 = atoi(optarg);
                break;
            case 'o': /* Secondary 20 is above or below primary 20 channel */
                channel_switch_req.sec_chan_offset = atoi(optarg);
                break;
            case 'n': /* Number of channel switch announcement frames */
                channel_switch_req.num_csa = atoi(optarg);
                break;
            case 'd': /* min dwell time  */
                channel_scan_req.min_dwell_time = atoi(optarg);
                break;
            case 'x': /* max dwell time  */
                channel_scan_req.max_dwell_time = atoi(optarg);
                break;
            case 'r': /* rest time  */
                channel_scan_req.rest_time = atoi(optarg);
                break;
            case 'm': /* scan active mode  */
                channel_scan_req.scan_mode = atoi(optarg);
                break;
            case 'e': /* channel to scan  */
                channel_scan_req.chanlist.n_chan = atoi(optarg);
                while (count < channel_scan_req.chanlist.n_chan) {
                    if (argv[++index] == NULL) {
                        fprintf(stdout, "Channel list invalid - Please provide %d channel(s) \n", channel_scan_req.chanlist.n_chan);
                        return -1;
                    }
                    channel_scan_req.chanlist.chan[count++] = atoi(argv[index]);
                }

                break;
            case 'q': /* SSID information of new Root AP */
                if (!(strlen(optarg) < sizeof(repeater_move_req.target_ssid.ssid))) {
                    fprintf(stdout, "SSID length invalid %s \n", optarg);
                    return -1;
                }
                if(strlcpy(repeater_move_req.target_ssid.ssid, optarg, sizeof(repeater_move_req.target_ssid.ssid)) >= sizeof(repeater_move_req.target_ssid.ssid)) {
                   printf("source too long");
                   return -1;
                }
                repeater_move_req.target_ssid.ssid_len = strlen(optarg);
                break;
            case 'b': /* BSSID information of new Root AP */
                if ((strlen(optarg) != 17)) {
                    fprintf(stdout, "BSSID length invalid %s \n", optarg);
                    return -1;
                }
                /*
                 * sscanf reads formatted input from a string and expects
                 * pointers to integers passed to it. Since target bssid information
                 * is stored as uint8 array, we first parse the BSSID with local
                 * variable of type int and then assign it to the target bssid
                 * of repeater move request structure. This is done to prevent warnings
                 * if reported by any compiler
                 */
                if (sscanf(optarg, "%x:%x:%x:%x:%x:%x",
                           &bssid[0],
                           &bssid[1],
                           &bssid[2],
                           &bssid[3],
                           &bssid[4],
                           &bssid[5]) < 6) {
                    fprintf(stdout, "Could not parse BSSID: %s\n", optarg);
                    return -1;
                }
                for (i = 0; i < BSSID_LEN; i++) {
                    repeater_move_req.target_bssid[i] = (uint8_t) bssid[i];
                }
                break;
            default:
                print_usage();
                break;
        }
    }

    if (subioctl_cmd == EXTENDED_SUBIOCTL_INVALID) {
        print_usage();
        return -1;
    }

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        err(1, "socket");
    }
    if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        printf("source too long\n");
        return -1;
    }
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    extended_cmd.cmd = subioctl_cmd;

    if (subioctl_cmd == EXTENDED_SUBIOCTL_CHANNEL_SWITCH) {
        extended_cmd.data = (caddr_t)&channel_switch_req;
        extended_cmd.data_len = sizeof(channel_switch_req);
    } else if (subioctl_cmd == EXTENDED_SUBIOCTL_CHANNEL_SCAN) {
        if (validate_scan_param(&channel_scan_req)) {
            return -1;
        }
        extended_cmd.data = (caddr_t)&channel_scan_req;
        extended_cmd.data_len = sizeof(channel_scan_req);
    } else if (subioctl_cmd == EXTENDED_SUBIOCTL_REPEATER_MOVE) {
        /* Assign channel switch request parameters in repeater move request */
        repeater_move_req.chan_switch_req = channel_switch_req;
        extended_cmd.data = (caddr_t)&repeater_move_req;
        extended_cmd.data_len = sizeof(repeater_move_req);
    }

    ifr.ifr_data = (caddr_t) &extended_cmd;
    if (ioctl(s, SIOCGATHEXTENDED, &ifr) < 0) {
        err(1, "%s", ifr.ifr_name);
        return -1;
    }

    return 0;
}
