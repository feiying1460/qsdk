/*
 * Copyright (c) 2014,2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2014, Qualcomm Atheros, Inc.
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
 * Simple QCA specific tool to set thermal parameters for beeliner.
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
#include <err.h>
#include <ctype.h>

#include "if_athioctl.h"
#include <ol_if_thermal.h>

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

static int strnicmp (const char *str1, const char *str2, size_t len)
{
    int diff = -1;

    while (len && *str1)
    {
        --len;
        if ((diff = (toupper (*str1) - toupper (*str2))) != 0) {
            return diff;
        }
        str1++;
        str2++;
    }
    if (len) {
        return (*str2) ? -1 : 0;
    }
    return 0;
}


static int stricmp (const char *str1, const char *str2)
{
    int diff = -1;

    while (*str1 && *str2)
    {
        if ((diff = (toupper (*str1) - toupper (*str2))) != 0) {
            return diff;
        }
        str1++;
        str2++;
    }
    if (*str1 == *str2) {
        return 0;
    }
    return -1;
}

#define streq(a,b)  (stricmp(a,b) == 0)
#define strneq(a,b,c)  (strnicmp(a,b,c) == 0)

#define validate_and_set(var, val)  \
{   if (val >= 0) {                 \
        var = val;                  \
    } else {                        \
        parse_err = TH_TRUE;        \
        break;                      \
    }                               \
}

#define set_level_val(level, var, val)                  \
{                                                       \
    th_config.levelconf[level].var = val;               \
}

#define validate_and_get_level(src, ps, level)          \
{                                                       \
    if ((src[strlen(ps)] >= '0') &&                     \
        (src[strlen(ps)] < '0' + THERMAL_LEVELS)) {     \
        level = atoi(&src[strlen(ps)]);                 \
    } else {                                            \
        parse_err = TH_TRUE;                            \
        break;                                          \
    }                                                   \
}

const char *lower_th_str = "-lo";
const char *upper_th_str = "-hi";
const char *Tx_off_str = "-off";
const char *duty_cycle_str = "-dc";
const char *queue_prio_str = "-qp";
const char *policy_str = "-p";


int
main(int argc, char *argv[])
{

    struct th_config_t  th_config;
    struct th_config_t  *p_config;
    struct th_stats_t   *p_stats;
    struct thermal_param get_param;
    struct extended_ioctl_wrapper extended_cmd;
    char ifname[20] = {'\0', };
    int s, i, argi;
    struct ifreq ifr;
    unsigned int subioctl_cmd = EXTENDED_SUBIOCTL_INVALID;
    int help_request = TH_FALSE;
    char *p = NULL;
    int parse_err = TH_FALSE;
    int val = 0;
    u_int32_t level = 0;


    if (argc < 4) {
        parse_err = TH_TRUE;
    }
    memset(&th_config, INVALID_BYTE, sizeof(th_config));
                    

    for (argi = 1; argi < argc; argi++) {
        p = &argv[argi][0];
        if (strneq(p, "-help", 5) || strneq(p, "--help", 6) ||
            strneq(p, "-use", 4) || strneq(p, "--use", 5)) {
            help_request = TH_TRUE;
        } else if (streq(p, "-set")) {
            subioctl_cmd = EXTENDED_SUBIOCTL_THERMAL_SET_PARAM;
        } else if (streq(p, "-get")) {
            subioctl_cmd = EXTENDED_SUBIOCTL_THERMAL_GET_PARAM;
            break;
        } else if (streq(p, "-i")) {
            ++argi;
            if (strlcpy(ifname, argv[argi], sizeof(ifr.ifr_name)) >= sizeof (ifr.ifr_name)){
                fprintf(stderr, "Interface name too long %s\n", argv[argi]);
                return -1;
            }
        } else if (streq(p, "-e")) {
            ++argi;
            val = atoi(argv[argi]);
            if ((val == THERMAL_MITIGATION_DISABLED) || (val == THERMAL_MITIGATION_ENABLED)) {
                validate_and_set(th_config.enable, val);
            } else {
                parse_err = TH_TRUE;
            }
        } else if (streq(p, "-et")) {
            ++argi;
            val = atoi(argv[argi]);
            if (val > 0) {
                validate_and_set(th_config.dc_per_event, val);
            } else {
                parse_err = TH_TRUE;
            }
        } else if (streq(p, "-dl")) {
            ++argi;
            val = atoi(argv[argi]);
            if (val > 0) {
                validate_and_set(th_config.log_lvl, val);
            } else {
                parse_err = TH_TRUE;
            }
        } else if (streq(p, duty_cycle_str)) {
            ++argi;
            val = atoi(argv[argi]);
            if (val > 0) {
                validate_and_set(th_config.dc, val);
            } else {
                parse_err = TH_TRUE;
            }
        } else if (strneq(p, policy_str, strlen(policy_str))) {
            validate_and_get_level(p, policy_str, level);
            ++argi;
            val = atoi(argv[argi]);
            /* As of now only queue pass TT scheme is supported */
            if (val == THERMAL_POLICY_QUEUE_PAUSE) {
                set_level_val(level, policy, val);
            } else {
                fprintf(stdout, "Only THERMAL_POLICY_QUEUE_PAUSE:(%d) is supported\n", THERMAL_POLICY_QUEUE_PAUSE);
                return -1;
            }
        } else if (strneq(p, lower_th_str, strlen(lower_th_str))) {
            validate_and_get_level(p, lower_th_str, level);
            ++argi;
            val = atoi(argv[argi]);
            set_level_val(level, tmplwm, val);
        } else if (strneq(p, upper_th_str, strlen(upper_th_str))) {
            validate_and_get_level(p, upper_th_str, level);
            ++argi;
            val = atoi(argv[argi]);
            set_level_val(level, tmphwm, val);
        } else if (strneq(p, Tx_off_str, strlen(Tx_off_str))) {
            validate_and_get_level(p, Tx_off_str, level);
            ++argi;
            val = atoi(argv[argi]);
            set_level_val(level, dcoffpercent, val);
        } else if (strneq(p, queue_prio_str, strlen(queue_prio_str))) {
            validate_and_get_level(p, queue_prio_str, level);
            ++argi;
            val = atoi(argv[argi]);
            set_level_val(level, priority, val);
        } else {
            parse_err = TH_TRUE;
        }
        if (parse_err == TH_TRUE) {
            break;
        }
    }

    if (((subioctl_cmd == EXTENDED_SUBIOCTL_THERMAL_SET_PARAM) && (argc < 6))     ||
            ((subioctl_cmd == EXTENDED_SUBIOCTL_THERMAL_GET_PARAM) && (argc < 4)) ||
            (subioctl_cmd == EXTENDED_SUBIOCTL_INVALID)) {
        parse_err = TH_TRUE;
    }

    if (parse_err == TH_TRUE || help_request == TH_TRUE) {
        fprintf(stdout, "Uses: thermaltool -i wifiX -e [0/1: enable/disable] -et [event time in dutycycle units]"
                        " -dc [duty cycle in ms] -dl [debug level] -pN [policy for lvl N] -loN [low th for lvl N] - hiN"
                        " [high th for lvl N] -offN [Tx Off time for lvl N] -qpN [TxQ priority lvl N]\n");

        return -1;
    }


    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        err(1, "socket");
    }
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    
    extended_cmd.cmd = subioctl_cmd;

    if (subioctl_cmd == EXTENDED_SUBIOCTL_THERMAL_SET_PARAM) {
        extended_cmd.data = (caddr_t)&th_config;
    } else if (subioctl_cmd == EXTENDED_SUBIOCTL_THERMAL_GET_PARAM) {
        extended_cmd.data = (caddr_t)&get_param;
    }

    ifr.ifr_data = (caddr_t) &extended_cmd;
    if (ioctl(s, SIOCGATHEXTENDED, &ifr) < 0) {
        err(1, "%s", ifr.ifr_name);
        return 0;
    }

    if (subioctl_cmd == EXTENDED_SUBIOCTL_THERMAL_GET_PARAM) {
        p_config = &(get_param.th_cfg);
        p_stats = &(get_param.th_stats);
    
        fprintf(stdout, "Thermal config for %s\n", ifname);
        fprintf(stdout, "  enable: %d, dc: %d, dc_per_event: %d\n",p_config->enable, p_config->dc, p_config->dc_per_event);
        for (i = 0; i < THERMAL_LEVELS; i++) {
            fprintf(stdout, "  level: %d, low thresold: %d, high thresold: %d, dcoffpercent: %d, queue priority %d, policy; %d\n",
                            i, p_config->levelconf[i].tmplwm, p_config->levelconf[i].tmphwm, p_config->levelconf[i].dcoffpercent,
                            p_config->levelconf[i].priority, p_config->levelconf[i].policy);
        }
        fprintf(stdout, "Thermal stats for %s\n", ifname);
        fprintf(stdout, "  sensor temperature: %d, current level: %d\n",p_stats->temp, p_stats->level);
        for (i = 0; i < THERMAL_LEVELS; i++) {
            fprintf(stdout, "  level: %d, entry count: %d, duty cycle spent: %d\n",
                            i, p_stats->levstats[i].levelcount, p_stats->levstats[i].dccount); 
        }
    } 

    return 0;
}

