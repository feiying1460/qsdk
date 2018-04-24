/*
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
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
 * wlanconfig athX create wlandev wifiX
 *	wlanmode station | adhoc | ibss | ap | monitor [bssid | -bssid]
 * wlanconfig athX destroy
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <err.h>


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>

#ifdef ANDROID
#include <compat.h>
#endif

/*
 * Linux uses __BIG_ENDIAN and __LITTLE_ENDIAN while BSD uses _foo
 * and an explicit _BYTE_ORDER.  Sorry, BSD got there first--define
 * things in the BSD way...
 */
#ifndef	_LITTLE_ENDIAN
#define	_LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#endif
#ifndef	_BIG_ENDIAN
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
#if QCA_AIRTIME_FAIRNESS
#define ATF_STA_NUM            50
#define ATF_VAP_NUM            16
struct addssid_val{
    uint16_t    id_type;
    uint8_t     ssid[IEEE80211_NWID_LEN+1];
    uint32_t    value;
};

struct addsta_val{
    uint16_t    id_type;
    uint8_t     sta_mac[IEEE80211_ADDR_LEN];
    uint8_t     ssid[IEEE80211_NWID_LEN+1];
    uint32_t    value;
};

struct addgroup_val{
    uint16_t    id_type;
    u_int8_t    name[32];
    uint8_t     ssid[IEEE80211_NWID_LEN+1];
    uint32_t    value;
};

#endif

/*
 * These are taken from ieee80211_node.h
 */

#define IEEE80211_NODE_TURBOP	0x0001		/* Turbo prime enable */
#define IEEE80211_NODE_AR	0x0010		/* AR capable */
#define IEEE80211_NODE_BOOST	0x0080
#define MACSTR_LEN 18

#define	streq(a,b)	(strncasecmp(a,b,sizeof(b)-1) == 0)

static int vap_create(struct ifreq *);
static void vap_destroy(const char *ifname);
static void list_stations(const char *ifname, int ps_activity); /* ps_activity: power save activity */
static void list_stations_human_format(const char *ifname);
static void list_scan(const char *ifname);
static void list_channels(const char *ifname, int allchans);
static void list_keys(const char *ifname);
static void list_capabilities(const char *ifname);
static void list_wme(const char *ifname);
static void ieee80211_status(const char *ifname);

static void usage(void);
static int getopmode(const char *, u_int32_t *);
static int getflag(const char *);
static int getvapid(const char *);
static int get80211param(const char *ifname, int param, void * data, size_t len);
static int set80211priv(const char *ifname, int op, void *data, size_t len);
static int get80211priv(const char *ifname, int op, void *data, size_t len);
static int getsocket(void);
static int set_p2p_noa(const char *ifname, char ** curargs );
static int get_noainfo(const char *ifname);
#if UMAC_SUPPORT_NAWDS
static int handle_nawds(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
			char *mac, int caps);
#endif

#if UMAC_SUPPORT_WNM
static int handle_wnm(const char *ifname, int cmd, const char *,
                                                    const char *);
#endif

#if defined(ATH_SUPPORT_HYFI_ENHANCEMENTS)
static int handle_hmwds(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
                        char *addr1, char *addr2);
static int handle_ald(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
                        char *addr1, int enable);
#endif

#ifdef ATH_BUS_PM
static int suspend(const char *ifname, int suspend);
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static int handle_hmmc(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
                        char *ip_str, char *mask_str);
#endif
static int set_max_rate(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
                        char *macaddr, u_int8_t maxrate);

size_t strlcat(char *dst, const char *src, size_t siz);

#if ATH_SUPPORT_WRAP
static int handle_macaddr(char *mac_str, u_int8_t *mac_addr);
#endif

#if QCA_AIRTIME_FAIRNESS
static void set_addssid_pval(const char *ifname, char *ssid, char *val);
static void set_delssid(const char *ifname, char *ssid);
static void set_addsta_pval(const char *ifname, char *macaddr, char *val, char *ssid);
static void set_delsta(const char *ifname, char *macaddr);
static void showatftable(const char *ifname, char *show_per_peer_table);
static void showairtime(const char *ifname);
static void flushatftable(const char *ifname);
static void set_addatfgroup(const char *ifname, char *groupname, char *ssid);
static void set_configatfgroup(const char *ifname, char *groupname, char *val);
static void set_delatfgroup(const char *ifname, char *groupname);
static void showatfgroup(const char *ifname);
static int atf_addsta_tput(const char *ifname, char *macaddr, char *val, char *val2);
static int atf_delsta_tput(const char *ifname, char *macaddr);
static int atf_show_tput(const char *ifname);
#endif

#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
static int handle_vendorie(const char *ifname,  IEEE80211_WLANCONFIG_CMDTYPE  cmdtype,
		int len, char *oui, char *pdata, char*ftype_map);
#endif

static int atf_show_stat(const char *ifname, char *macaddr);

#if ATH_SUPPORT_NAC
static int handle_nac(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,	int argc, char *argv[]);
#endif

int	verbose = 0;

int
main(int argc, char *argv[])
{
	const char *ifname, *cmd;
    char *errorop;
    u_int8_t temp = 0, rate = 0;
    int status = 0;

	if (argc < 3)
		usage();

	ifname = argv[1];
	cmd = argv[2];
	if (streq(cmd, "create")) {
		struct ieee80211_clone_params cp;
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));

		memset(&cp, 0, sizeof(cp));
		if (strlcpy(cp.icp_name, ifname, sizeof(cp.icp_name)) >= sizeof(cp.icp_name)) {
			fprintf(stderr, "ifname %s too long\n", ifname);
			exit(-1);
		}
		/* NB: station mode is the default */
		cp.icp_opmode = IEEE80211_M_STA;
		/* NB: default is to request a unique bssid/mac */
		cp.icp_flags = IEEE80211_CLONE_BSSID;

		while (argc > 3) {
			if (strcmp(argv[3], "wlanmode") == 0) {
				if (argc < 5)
					usage();
				cp.icp_opmode = (u_int16_t) getopmode(argv[4], &cp.icp_flags);
				argc--, argv++;
			} else if (strcmp(argv[3], "wlandev") == 0) {
				if (argc < 5)
					usage();
                                memset(ifr.ifr_name, '\0', IFNAMSIZ);
				if (strlcpy(ifr.ifr_name, argv[4], sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
					fprintf(stderr, "ifname %s too long\n", argv[4]);
					exit(-1);
				}
				argc--, argv++;
#if ATH_SUPPORT_WRAP
            } else if (strcmp(argv[3], "wlanaddr") == 0) {
                if (argc < 5)
                    usage();
                handle_macaddr(argv[4], cp.icp_bssid);
                cp.icp_flags &= ~IEEE80211_CLONE_BSSID;
                cp.icp_flags |= IEEE80211_CLONE_MACADDR;
                argc--, argv++;
            } else if (strcmp(argv[3], "mataddr") == 0) {
                if (argc < 5)
                    usage();
                handle_macaddr(argv[4], cp.icp_mataddr);
                cp.icp_flags |= IEEE80211_CLONE_MATADDR;
                argc--, argv++;
            } else if (strcmp(argv[3], "-bssid") == 0) {
                if (argc < 5)
                    usage();
                handle_macaddr(argv[4], cp.icp_bssid);
                cp.icp_flags &= ~(IEEE80211_CLONE_BSSID);
                argc--, argv++;
#endif
            } else if (strcmp(argv[3], "vapid") == 0) {
                if (argc < 5)
                    usage();
                int32_t vapid = getvapid(argv[4]);
                if (vapid >= 0 && vapid <= 15) {
                    cp.icp_vapid = vapid;
                    cp.icp_flags &= ~(IEEE80211_CLONE_BSSID);
                } else {
                    usage();
                }
                argc--, argv++;
	    } else {
		int flag = getflag(argv[3]);
		if (flag < 0)
			cp.icp_flags &= ~(-flag);
		else
			cp.icp_flags |= flag;
	    }
			argc--, argv++;
	  }
		if (ifr.ifr_name[0] == '\0')
			errx(1, "no device specified with wlandev");
		ifr.ifr_data = (void *) &cp;
		status = vap_create(&ifr);
	} else if (streq(cmd, "destroy")) {
		vap_destroy(ifname);
	} else if (streq(cmd, "list")) {
		int ps_activity = 0;
		if (argc > 3) {
			const char *arg = argv[3];

			if (streq(arg, "sta")) {
				if (argc > 4)
				{
					const char *arg_activity = argv[4];
					if (streq(arg_activity, "psactivity")) {
					ps_activity = 1;
					}
				}
				list_stations(ifname, ps_activity);
                        }
			else if (streq(arg, "scan") || streq(arg, "ap"))
				list_scan(ifname);
			else if (streq(arg, "chan") || streq(arg, "freq"))
				list_channels(ifname, 1);
			else if (streq(arg, "active"))
				list_channels(ifname, 0);
			else if (streq(arg, "keys"))
				list_keys(ifname);
			else if (streq(arg, "caps"))
				list_capabilities(ifname);
			else if (streq(arg, "wme"))
				list_wme(ifname);
			else if (streq(arg, "-H"))
				list_stations_human_format(ifname);
		} else				/* NB: for compatibility */
			list_stations(ifname, ps_activity);
#if UMAC_SUPPORT_NAWDS
	} else if (streq(cmd, "nawds")) {
		if (argc == 5 && streq(argv[3], "mode")) {
			return handle_nawds(ifname, IEEE80211_WLANCONFIG_NAWDS_SET_MODE,
					NULL, atoi(argv[4]));
		} else if (argc == 5 && streq(argv[3], "defcaps")) {
			return handle_nawds(ifname, IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS,
					NULL, strtoul(argv[4], NULL, 0));
		} else if (argc == 5 && streq(argv[3], "override")) {
			return handle_nawds(ifname, IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE,
					NULL, atoi(argv[4]));
		} else if (argc == 6 && streq(argv[3], "add-repeater")) {
			return handle_nawds(ifname, IEEE80211_WLANCONFIG_NAWDS_SET_ADDR,
					argv[4], strtoul(argv[5], NULL, 0));
		} else if (argc == 5 && streq(argv[3], "del-repeater")) {
			return handle_nawds(ifname, IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR,
					argv[4], 0);
		} else if (argc == 4 && streq(argv[3], "list")) {
			return handle_nawds(ifname, IEEE80211_WLANCONFIG_NAWDS_GET,
					argv[4], 0);
		} else {
			errx(1, "invalid NAWDS command");
		}
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	} else if (streq(cmd, "hmwds")) {
		if (argc == 6 && streq(argv[3], "add-addr")) {
			return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR,
					argv[4], argv[5]);
        } else if (argc == 5 && streq(argv[3], "reset-addr")) {
			return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR,
					argv[4], NULL);
        } else if (argc == 4 && streq(argv[3], "reset-table")) {
			return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE,
					NULL, NULL);
        } else if (argc == 5 && streq(argv[3], "read-addr")) {
			return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_READ_ADDR,
					argv[4], NULL);
        } else if (argc == 4 && streq(argv[3], "read-table")) {
			return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_READ_TABLE,
					NULL, NULL);
        } else if (argc == 5 && streq(argv[3], "rem-addr")) {
                        return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR,
                                        argv[4], NULL);
        } else if (argc == 4 && streq(argv[3], "dump-wdstable")) {
                        return handle_hmwds(ifname, IEEE80211_WLANCONFIG_HMWDS_DUMP_WDS_ADDR,
                                        argv[4], NULL);
		} else {
			errx(1, "invalid HMWDS command");
		}
	} else if (streq(cmd, "ald")) {
		if (argc == 6 && streq(argv[3], "sta-enable")) {
			return handle_ald(ifname, IEEE80211_WLANCONFIG_ALD_STA_ENABLE,
					argv[4], atoi(argv[5]));
		} else {
			errx(1, "invalid ALD command");
		}
#endif
#if UMAC_SUPPORT_WNM
    } else if(streq(cmd, "wnm")) {
        if (argc < 4) {
             errx(1, "err : Insufficient arguments \n");
        }
        if (streq(argv[3], "setbssmax")) {
            if (argc < 5) {
                errx(1, "usage: wlanconfig athX wnm setbssmax");
            } else if (argc == 5) {
                argv[5] = 0;
            }
            handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_SET_BSSMAX,
                                             argv[4], argv[5]);
        }
        if (streq(argv[3], "getbssmax")) {
            handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_GET_BSSMAX, 0, 0);
        }
        if (streq(argv[3], "tfsreq")) {
            if (argc < 4) {
	    		errx(1, "no input file specified");
            }
            handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_TFS_ADD, argv[4], 0);
        }
        if (streq(argv[3], "deltfs")) {
            handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_TFS_DELETE, 0, 0);
        }
        if (streq(argv[3], "fmsreq")) {
            handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY,  argv[4], 0);
        }
        if (streq(argv[3], "gettimparams")) {
            handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST,
                                                           0, 0);
        }
        if (streq(argv[3], "timintvl")) {
            if (argc < 4) {
                errx(1, "err : Enter TimInterval in number of Beacons");
            } else {
                handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST,
                                                   argv[4], 0);
            }
        }
        if (streq(argv[3], "timrate")) {
            char temp[10];
            if (argc < 6) {
                errx(1, "invalid args");
            } else {
                snprintf(temp, sizeof(temp), "%d", (!!atoi(argv[4]) | !!atoi(argv[5]) << 1));

                handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST, 0, temp);
            }
        }
        /* BSS Termination */
        if (streq(argv[3], "bssterm")) {
            if (argc < 5) {
                errx(1, "usage: wlanconfig athX wnm bssterm <delay in TBTT> <duration in minutes>");
            } else {
                if (argc == 5)
                    argv[5] = 0;
                handle_wnm(ifname, IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION, argv[4], argv[5]);
            }
        }
#endif
	} else if (streq(cmd, "p2pgo_noa")) {
        return set_p2p_noa(ifname,&argv[3]);
	} else if (streq(cmd, "noainfo")) {
        return get_noainfo(ifname);
#ifdef ATH_BUS_PM
    } else if (streq(cmd, "suspend")) {
      return suspend(ifname, 1);
    } else if (streq(cmd, "resume")) {
      return suspend(ifname, 0);
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    } else if (streq(cmd, "hmmc")) {
		if (argc == 4 && streq(argv[3], "dump")) {
			return handle_hmmc(ifname, IEEE80211_WLANCONFIG_HMMC_DUMP, NULL, NULL);
        } else if (argc == 6 && streq(argv[3], "add")) {
			return handle_hmmc(ifname, IEEE80211_WLANCONFIG_HMMC_ADD, argv[4], argv[5]);
        } else if (argc == 6 && streq(argv[3], "del")) {
			return handle_hmmc(ifname, IEEE80211_WLANCONFIG_HMMC_DEL, argv[4], argv[5]);
			errx(1, "invalid HMMC command");
        }
#endif
    } else if (streq(cmd, "set_max_rate")) {
        if (argc < 5) {
            errx(1, "Insufficient Number of Arguements\n");
        } else {
            temp = strtoul(argv[4], &errorop, 16);
            rate = temp;
            return set_max_rate(ifname, IEEE80211_WLANCONFIG_SET_MAX_RATE,
                                argv[3], rate);
         }
    }
#if ATH_SUPPORT_DYNAMIC_VENDOR_IE

#define ARG_COUNT_VENDOR_IE_ADD_OR_UPDATE 12    /* check wlanconfig help */
#define ARG_COUNT_VENDOR_IE_REMOVE 10    /* check wlanconfig help */
#define ARG_COUNT_VENDOR_IE_LIST 8    /* check wlanconfig help */
#define ARG_COUNT_VENDOR_IE_LIST_ALL 4      /* check wlanconfig help */

    else if (streq(cmd, "vendorie")) {

        if (argc == ARG_COUNT_VENDOR_IE_ADD_OR_UPDATE && streq(argv[3], "add")) {
            if (streq(argv[4], "len") && streq(argv[6], "oui") && streq(argv[8], "pcap_data") && streq(argv[10], "ftype_map")) {
                return handle_vendorie (ifname, IEEE80211_WLANCONFIG_VENDOR_IE_ADD,
                                        atoi(argv[5]), argv[7], argv[9], argv[11]);
            } else {
                errx(1, "invalid vendorie command , check wlanconfig help");
            }
        } else if (argc == ARG_COUNT_VENDOR_IE_ADD_OR_UPDATE && streq(argv[3], "update")) {
            if (streq(argv[4], "len") && streq(argv[6], "oui") && streq(argv[8], "pcap_data") && streq(argv[10], "ftype_map")) {
                return handle_vendorie (ifname, IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE,
                                        atoi(argv[5]), argv[7], argv[9], argv[11]);
            } else {
                errx(1, "invalid vendorie command , check wlanconfig help");
            }
        } else if (argc == ARG_COUNT_VENDOR_IE_REMOVE && streq(argv[3], "remove")) {
            if (streq(argv[4], "len") && streq(argv[6], "oui") && streq(argv[8], "pcap_data")){
                return handle_vendorie (ifname, IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE,
                                    atoi(argv[5]), argv[7], argv[9], NULL);
            } else {
                errx(1, "invalid vendorie command , check wlanconfig help");
            }
        } else if (argc == ARG_COUNT_VENDOR_IE_LIST && streq(argv[3], "list")) {
            if (streq(argv[4], "len") && streq(argv[6], "oui")){
                return handle_vendorie (ifname, IEEE80211_WLANCONFIG_VENDOR_IE_LIST,
                                    atoi(argv[5]), argv[7], NULL, NULL);
            }
            else {
                errx(1, "invalid vendorie command , check wlanconfig help");
            }
        } else if (argc == ARG_COUNT_VENDOR_IE_LIST_ALL && streq(argv[3], "list")) {
            return handle_vendorie (ifname, IEEE80211_WLANCONFIG_VENDOR_IE_LIST,
                                   0 , NULL, NULL, NULL);
        }
        else {
            errx(1, "Invalid vendorie command , check wlanconfig help");
        }
    }
#endif

    else if (streq(cmd, "atfstat")) {
        if (argc > 3)
            atf_show_stat(ifname, argv[3]);
        else
            fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
    }

#if ATH_SUPPORT_NAC
    else if (streq(cmd, "nac")) {

        if(streq(argv[3], "add") && streq(argv[4], "bssid") && (argc >= 6 && argc <=8)){
            return handle_nac (ifname, IEEE80211_WLANCONFIG_NAC_ADDR_ADD,
                                        argc , argv);
        } else if(streq(argv[3], "add") && streq(argv[4], "client") && (argc >= 6 && argc <=13)){
            return handle_nac (ifname, IEEE80211_WLANCONFIG_NAC_ADDR_ADD,
                                        argc , argv);
        } else if(streq(argv[3], "del") && streq(argv[4], "bssid") && (argc >= 6 && argc <=8)){
            return handle_nac (ifname, IEEE80211_WLANCONFIG_NAC_ADDR_DEL,
                                        argc , argv);
        } else if(streq(argv[3], "del") && streq(argv[4], "client") && (argc >= 6 && argc <=13)){
            return handle_nac (ifname, IEEE80211_WLANCONFIG_NAC_ADDR_DEL,
                                        argc , argv);
        } else if(streq(argv[3], "list") && (argc == 5 )){
            return handle_nac (ifname, IEEE80211_WLANCONFIG_NAC_ADDR_LIST,
                                        argc , argv);
        } else {
            errx(1, "Invalid vendorie command , check wlanconfig help");
        }
    }
#endif

#if QCA_AIRTIME_FAIRNESS
    else if (strncmp(ifname,"ath",3) == 0) {
        if (argc >= 2) {
            if (streq(argv[2], "addssid"))
            {
               if(argc != 5)
               {
                  fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
               }else{
                  set_addssid_pval(ifname,argv[3],argv[4]);
               }
            }else if (streq(argv[2], "delssid")){
               if(argc != 4)
               {
                  fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
               }else{
                  set_delssid(ifname,argv[3]);
               }
            }else if (streq(argv[2], "addsta")){
               if (argc >= 6)
                   set_addsta_pval(ifname, argv[3], argv[4], argv[5]);
               else if (argc >= 5)
                   set_addsta_pval(ifname, argv[3], argv[4], NULL);
               else
                   fprintf(stderr, "Missing Parameters %d\n", argc);
            }else if (streq(argv[2], "delsta")){
               if(argc != 4)
               {
                  fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
               }else{
                  set_delsta(ifname,argv[3]);
               }
            }else if (streq(argv[2], "showatftable")){
               fprintf(stderr,"\n\n                      SHOW   ATF    TABLE  \n");
               if(argc >= 4)
               {
                  showatftable(ifname,argv[3]);
               }else{
                  showatftable(ifname,NULL);
               }
            }else if (streq(argv[2], "showairtime")){
               fprintf(stderr,"\n\n                      SHOW   AIRTIME    TABLE  \n");
               showairtime(ifname);
            } else if (streq(argv[2], "flushatftable")){
                flushatftable(ifname);
            } else if (streq(argv[2], "addatfgroup")){
                if(argc != 5)
                {
                    fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
                } else {
                    set_addatfgroup(ifname, argv[3], argv[4]);
                }
            }else if (streq(argv[2], "configatfgroup")){
                if(argc != 5)
                {
                    fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
                } else {
                    set_configatfgroup(ifname, argv[3], argv[4]);
                }
            }else if (streq(argv[2], "delatfgroup")){
                if(argc != 4)
                {
                    fprintf(stderr,"\n\n     Missing parameters!!  \n\n");
                } else {
                    set_delatfgroup(ifname, argv[3]);
                }
            }else if (streq(argv[2], "showatfgroup")){
                fprintf(stderr,"\n\n                      SHOW   ATF    GROUP  \n");
                showatfgroup(ifname);
            } else if (streq(argv[2], "addtputsta")) {
                if (argc >= 6)
                    atf_addsta_tput(ifname, argv[3], argv[4], argv[5]);
                else if (argc >= 5)
                    atf_addsta_tput(ifname, argv[3], argv[4], NULL);
                else
                    fprintf(stderr, "Missing Parameters %d\n", argc);
            } else if (streq(argv[2], "deltputsta")) {
                if (argc >= 4)
                    atf_delsta_tput(ifname, argv[3]);
                else
                    fprintf(stderr, "Missing Parameters %d\n", argc);
            } else if (streq(argv[2], "showtputtbl")) {
                atf_show_tput(ifname);
            }
        }
    }
#endif
    else
		ieee80211_status(ifname);

    if(status != 0)
        return status;

	return 0;
}

static int
vap_create(struct ifreq *ifr)
{
	char oname[IFNAMSIZ];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		err(1, "socket(SOCK_DRAGM)");
        memset(oname, '\0', sizeof(oname));
	if (strlcpy(oname, ifr->ifr_name, sizeof(oname)) >= sizeof(oname)) {
		close(s);
		fprintf(stderr, "VAP name too long\n");
		exit(-1);
	}
	if (ioctl(s, SIOC80211IFCREATE, ifr) != 0) {
		err(1, "ioctl");
                return -1;
        }
	/* NB: print name of clone device when generated */
	if (memcmp(oname, ifr->ifr_name, IFNAMSIZ) != 0)
		printf("%s\n", ifr->ifr_name);

        close(s);
        return 0;
}

static void
vap_destroy(const char *ifname)
{
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		err(1, "socket(SOCK_DRAGM)");
	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
		fprintf(stderr, "ifname too long: %s\n", ifname);
		close(s);
		exit(-1);
	}
	if (ioctl(s, SIOC80211IFDESTROY, &ifr) < 0)
		err(1, "ioctl");
	close(s);
}

static void
usage(void)
{
	fprintf(stderr, "usage: wlanconfig athX create wlandev wifiX\n");
#if MESH_MODE_SUPPORT
    fprintf(stderr, "                  wlanmode [sta|adhoc|ap|monitor|wrap|p2pgo|p2pcli|p2pdev|specialvap|mesh|smart_monitor|lp_iot_mode]\n"
                    "                  [wlanaddr <mac_addr>] [mataddr <mac_addr>] [bssid|-bssid] [vapid <0-15>] [nosbeacon]\n");
#else
    fprintf(stderr, "                  wlanmode [sta|adhoc|ap|monitor|wrap|p2pgo|p2pcli|p2pdev|specialvap|smart_monitor|lp_iot_mode]\n"
                    "                  [wlanaddr <mac_addr>] [mataddr <mac_addr>] [bssid|-bssid] [vapid <0-15>] [nosbeacon]\n");
#endif
	fprintf(stderr, "usage: wlanconfig athX destroy\n");
#if UMAC_SUPPORT_NAWDS
	fprintf(stderr, "usage: wlanconfig athX nawds mode (0-4)\n");
	fprintf(stderr, "usage: wlanconfig athX nawds defcaps CAPS\n");
	fprintf(stderr, "usage: wlanconfig athX nawds override (0-1)\n");
	fprintf(stderr, "usage: wlanconfig athX nawds add-repeater MAC (0-1)\n");
	fprintf(stderr, "usage: wlanconfig athX nawds del-repeater MAC\n");
	fprintf(stderr, "usage: wlanconfig athX nawds list\n");
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	fprintf(stderr, "usage: wlanconfig athX hmwds add-addr wds_ni_macaddr wds_macaddr\n");
	fprintf(stderr, "usage: wlanconfig athX hmwds reset-addr macaddr\n");
	fprintf(stderr, "usage: wlanconfig athX hmwds reset-table\n");
	fprintf(stderr, "usage: wlanconfig athX hmwds read-addr wds_ni_macaddr\n");
        fprintf(stderr, "usage: wlanconfig athX hmwds dump-wdstable\n");
	fprintf(stderr, "usage: wlanconfig athX hmwds read-table\n");
	fprintf(stderr, "usage: wlanconfig athX hmwds rem-addr <mac_addr>\n");
	fprintf(stderr, "usage: wlanconfig athX ald sta-enable <sta_mac_addr> <0/1>\n");

#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    fprintf(stderr, "usage: wlanconfig athX hmmc add ip mask\n");
    fprintf(stderr, "usage: wlanconfig athX hmmc del ip mask\n");
    fprintf(stderr, "usage: wlanconfig athX hmmc dump\n");
#endif
#if UMAC_SUPPORT_WNM
	fprintf(stderr, "usage: wlanconfig athX wnm setbssmax"
                    " <idle period in seconds> [<idle option>]\n");
	fprintf(stderr, "usage: wlanconfig athX wnm getbssmax\n");
	fprintf(stderr, "usage: wlanconfig athX wnm tfsreq <filename>\n");
	fprintf(stderr, "usage: wlanconfig athX wnm deltfs\n");
	fprintf(stderr, "usage: wlanconfig athX wnm timintvl <Interval> \n");
	fprintf(stderr, "usage: wlanconfig athX wnm gettimparams\n");
	fprintf(stderr, "usage: wlanconfig athX wnm timrate "
                    "<highrateEnable> <lowRateEnable> \n");
    fprintf(stderr, "usage: wlanconfig athX wnm bssterm "
                    "<delay in TBTT> [<duration in minutes>]\n");
#endif
#ifdef ATH_BUS_PM
	fprintf(stderr, "usage: wlanconfig wifiX suspend|resume\n");
#endif
#if QCA_AIRTIME_FAIRNESS
    fprintf(stderr, "usage: wlanconfig athX addssid ssidname per_value(0--100)\n");
    fprintf(stderr, "usage: wlanconfig athX addsta  macaddr(example:112233445566) per_value(0--100)\n");
    fprintf(stderr, "usage: wlanconfig athX delssid ssidname\n");
    fprintf(stderr, "usage: wlanconfig athX delsta  macaddr\n");
    fprintf(stderr, "usage: wlanconfig athX showatftable [show_per_peer_table<1>]\n");
    fprintf(stderr, "usage: wlanconfig athX showairtime\n");
    fprintf(stderr, "usage: wlanconfig athX flushatftable\n");
    fprintf(stderr, "usage: wlanconfig athX addatfgroup groupname ssid\n");
    fprintf(stderr, "usage: wlanconfig athX configatfgroup groupname value (0 - 100))\n");
    fprintf(stderr, "usage: wlanconfig athX delatfgroup groupname\n");
    fprintf(stderr, "usage: wlanconfig athX showatfgroup\n");
    fprintf(stderr, "usage: wlanconfig athX addtputsta macaddr tput airtime(opt)\n");
    fprintf(stderr, "usage: wlanconfig athX deltputsta macaddr\n");
    fprintf(stderr, "usage: wlanconfig athX showtputtbl\n");
    fprintf(stderr, "usage: wlanconfig athX atfstat\n");
#endif
#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
	fprintf(stderr, "usage: wlanconfig athX vendorie add len <oui+pcap_data in bytes> oui <eg:xxxxxx> pcap_data <eg:xxxxxxxx> ftype_map <eg:xx>\n");
	fprintf(stderr, "usage: wlanconfig athX vendorie update len <oui+pcap_data in bytes> oui <eg:xxxxxx> pcap_data <eg:xxxxxxxx> ftype_map <eg:xx>\n");
	fprintf(stderr, "usage: wlanconfig athX vendorie remove len <oui+pcap_data in bytes> oui <eg:xxxxxx> pcap_data <eg:xx>\n");
        fprintf(stderr, "usage: wlanconfig athX vendorie list \n");
	fprintf(stderr, "usage: wlanconfig athX vendorie list len <oui in bytes> oui <eg:xxxxxx>\n");
#endif
#if ATH_SUPPORT_NAC
	fprintf(stderr, "usage: wlanconfig athX nac add/del bssid <ad1 eg: xx:xx:xx:xx:xx:xx> <ad2> <ad3> \n");
	fprintf(stderr, "usage: wlanconfig athX nac add/del client <ad1 eg: xx:xx:xx:xx:xx:xx> <ad2> <ad3> <ad4> <ad5>  <ad6> <ad7>  <ad8>\n");
	fprintf(stderr, "usage: wlanconfig athX nac list bssid/client \n");
#endif
	exit(-1);
}

static int
getopmode(const char *s, u_int32_t *flags)
{
	if (streq(s, "sta"))
		return IEEE80211_M_STA;
	if (streq(s, "ibss") || streq(s, "adhoc"))
		return IEEE80211_M_IBSS;
	if (streq(s, "mon"))
		return IEEE80211_M_MONITOR;
	if (streq(s, "ap") || streq(s, "hostap")) {
		return IEEE80211_M_HOSTAP;
    }
#if 0
	/* EV 129529.commented this code,since this mode is not used */
	if (streq(s, "wds"))
		return IEEE80211_M_WDS;
#endif
    if (streq(s, "p2pgo"))
        return IEEE80211_M_P2P_GO;
    if (streq(s, "p2pcli"))
        return IEEE80211_M_P2P_CLIENT;
    if (streq(s, "p2pdev"))
        return IEEE80211_M_P2P_DEVICE;
    if (streq(s, "wrap")) {
        *flags |= IEEE80211_WRAP_VAP;
        return IEEE80211_M_HOSTAP;
    }
    if (streq(s, "specialvap")) {
        *flags |= IEEE80211_SPECIAL_VAP;
        return IEEE80211_M_HOSTAP;
    }
#if MESH_MODE_SUPPORT
    if (streq(s, "mesh")) {
        *flags |= IEEE80211_MESH_VAP;
        return IEEE80211_M_HOSTAP;
    }
#endif
#if ATH_SUPPORT_NAC
    if (streq(s, "smart_monitor")) {
        *flags |= IEEE80211_SMART_MONITOR_VAP;
        *flags |= IEEE80211_SPECIAL_VAP;
        return IEEE80211_M_HOSTAP;
    }
#endif
    if (streq(s, "lp_iot_mode")) {
        *flags |= IEEE80211_LP_IOT_VAP;
        return IEEE80211_M_HOSTAP;
    }
    errx(1, "unknown operating mode %s", s);
	/*NOTREACHED*/
	return -1;
}

static int
getvapid(const char *s)
{
    if (s != NULL) {
        return atoi(s);
    }
    errx(1, "Invalid vapid %s", s);
    return -1;
}

static int
getflag(const char  *s)
{
	const char *cp;
	int flag = 0;

	cp = (s[0] == '-' ? s+1 : s);
	if (strcmp(cp, "bssid") == 0)
		flag = IEEE80211_CLONE_BSSID;
	if (strcmp(cp, "nosbeacon") == 0)
		flag |= IEEE80211_NO_STABEACONS;
	if (flag == 0)
		errx(1, "unknown create option %s", s);
	return (s[0] == '-' ? -flag : flag);
}

/*
 * Convert IEEE channel number to MHz frequency.
 */
static u_int
ieee80211_ieee2mhz(u_int chan)
{
	if (chan == 14)
		return 2484;
	if (chan < 14)			/* 0-13 */
		return 2407 + chan*5;
	if (chan < 27)			/* 15-26 */
		return 2512 + ((chan-15)*20);
	return 5000 + (chan*5);
}

/*
 * Convert MHz frequency to IEEE channel number.
 */
static u_int
ieee80211_mhz2ieee(u_int freq)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)

	if (freq == 2484)
        return 14;
    if (freq < 2484)
        return (freq - 2407) / 5;
    if (freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
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

typedef u_int8_t uint8_t;

static int
getmaxrate(uint8_t rates[15], uint8_t nrates)
{
	int i, maxrate = -1;

	for (i = 0; i < nrates; i++) {
		int rate = rates[i] & IEEE80211_RATE_VAL;
		if (rate > maxrate)
			maxrate = rate;
	}
	return maxrate / 2;
}

static const char *
getcaps(int capinfo)
{
	static char capstring[32];
	char *cp = capstring;

	if (capinfo & IEEE80211_CAPINFO_ESS)
		*cp++ = 'E';
	if (capinfo & IEEE80211_CAPINFO_IBSS)
		*cp++ = 'I';
	if (capinfo & IEEE80211_CAPINFO_CF_POLLABLE)
		*cp++ = 'c';
	if (capinfo & IEEE80211_CAPINFO_CF_POLLREQ)
		*cp++ = 'C';
	if (capinfo & IEEE80211_CAPINFO_PRIVACY)
		*cp++ = 'P';
	if (capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)
		*cp++ = 'S';
	if (capinfo & IEEE80211_CAPINFO_PBCC)
		*cp++ = 'B';
	if (capinfo & IEEE80211_CAPINFO_CHNL_AGILITY)
		*cp++ = 'A';
	if (capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME)
		*cp++ = 's';
	if (capinfo & IEEE80211_CAPINFO_DSSSOFDM)
		*cp++ = 'D';
	*cp = '\0';
	return capstring;
}

static const char *
getathcaps(int capinfo)
{
	static char capstring[32];
	char *cp = capstring;

	if (capinfo & IEEE80211_NODE_TURBOP)
		*cp++ = 'D';
	if (capinfo & IEEE80211_NODE_AR)
		*cp++ = 'A';
	if (capinfo & IEEE80211_NODE_BOOST)
		*cp++ = 'T';
	*cp = '\0';
	return capstring;
}

static const char *
gethtcaps(int capinfo)
{
	static char capstring[32];
	char *cp = capstring;

	if (capinfo & IEEE80211_HTCAP_C_ADVCODING)
		*cp++ = 'A';
	if (capinfo & IEEE80211_HTCAP_C_CHWIDTH40)
		*cp++ = 'W';
	if ((capinfo & IEEE80211_HTCAP_C_SM_MASK) ==
             IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED)
		*cp++ = 'P';
	if ((capinfo & IEEE80211_HTCAP_C_SM_MASK) ==
             IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC)
		*cp++ = 'Q';
	if ((capinfo & IEEE80211_HTCAP_C_SM_MASK) ==
             IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC)
		*cp++ = 'R';
	if (capinfo & IEEE80211_HTCAP_C_GREENFIELD)
		*cp++ = 'G';
	if (capinfo & IEEE80211_HTCAP_C_SHORTGI40)
		*cp++ = 'S';
	if (capinfo & IEEE80211_HTCAP_C_DELAYEDBLKACK)
		*cp++ = 'D';
	if (capinfo & IEEE80211_HTCAP_C_MAXAMSDUSIZE)
		*cp++ = 'M';
	*cp = '\0';
	return capstring;
}

static void
printie(const char* tag, const uint8_t *ie, size_t ielen, int maxlen)
{
	printf("%s", tag);
	if (verbose) {
		maxlen -= strlen(tag)+2;
		if (2*ielen > maxlen)
			maxlen--;
		printf("<");
		for (; ielen > 0; ie++, ielen--) {
			if (maxlen-- <= 0)
				break;
			printf("%02x", *ie);
		}
		if (ielen != 0)
			printf("-");
		printf(">");
	}
}

/*
 * Copy the ssid string contents into buf, truncating to fit.  If the
 * ssid is entirely printable then just copy intact.  Otherwise convert
 * to hexadecimal.  If the result is truncated then replace the last
 * three characters with "...".
 */
static size_t
copy_essid(char buf[], size_t bufsize, const u_int8_t *essid, size_t essid_len)
{
	const u_int8_t *p;
	size_t maxlen;
	int i;
	size_t orig_bufsize =  bufsize;

	if (essid_len > bufsize)
		maxlen = bufsize;
	else
		maxlen = essid_len;
	/* determine printable or not */
	for (i = 0, p = essid; i < maxlen; i++, p++) {
		if (*p < ' ' || *p > 0x7e)
			break;
	}
	if (i != maxlen) {		/* not printable, print as hex */
		if (bufsize < 3)
			return 0;
		strlcpy(buf, "0x", bufsize);

		bufsize -= 2;
		p = essid;
		for (i = 0; i < maxlen && bufsize >= 2; i++) {
			snprintf(&buf[2 + (2 * i)], (bufsize - 2 + (2 * i)), "%02x", *p++);
			bufsize -= 2;
		}
		maxlen = (2 + (2 * i));
	} else {			/* printable, truncate as needed */
		memcpy(buf, essid, maxlen);
	}
	if (maxlen != essid_len)
		memcpy(buf+maxlen-3, "...", 3);

	/* Modify for static analysis, protect for buffer overflow */
	buf[orig_bufsize-1] = '\0';

	return maxlen;
}

/* unalligned little endian access */
#ifndef LE_READ_4
#define LE_READ_4(p)					\
	((u_int32_t)					\
	 ((((const u_int8_t *)(p))[0]      ) |		\
	  (((const u_int8_t *)(p))[1] <<  8) |		\
	  (((const u_int8_t *)(p))[2] << 16) |		\
	  (((const u_int8_t *)(p))[3] << 24)))
#endif

static int __inline
iswpaoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((WPA_OUI_TYPE<<24)|WPA_OUI);
}

static int __inline
iswmeoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI);
}

static int __inline
isatherosoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((ATH_OUI_TYPE<<24)|ATH_OUI);
}

static void
printies(const u_int8_t *vp, int ielen, int maxcols)
{
	while (ielen > 0) {
		switch (vp[0]) {
		case IEEE80211_ELEMID_VENDOR:
			if (iswpaoui(vp))
				printie(" WPA", vp, 2+vp[1], maxcols);
			else if (iswmeoui(vp))
				printie(" WME", vp, 2+vp[1], maxcols);
			else if (isatherosoui(vp))
				printie(" ATH", vp, 2+vp[1], maxcols);
			else
				printie(" VEN", vp, 2+vp[1], maxcols);
			break;
        case IEEE80211_ELEMID_RSN:
            printie(" RSN", vp, 2+vp[1], maxcols);
            break;
		default:
			printie(" ???", vp, 2+vp[1], maxcols);
			break;
		}
		ielen -= 2+vp[1];
		vp += 2+vp[1];
	}
}

static const char *
ieee80211_ntoa(const uint8_t mac[IEEE80211_ADDR_LEN])
{
	static char a[18];
	int i;

	i = snprintf(a, sizeof(a), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (i < 17 ? NULL : a);
}

#if QCA_AIRTIME_FAIRNESS
static int get_ssid(const char *ifname, char *ssid)
{
    struct iwreq iwr;
    int s, len;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
    }

    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return -1;
    }
    iwr.u.data.pointer = (void *)ssid;
    iwr.u.data.length = IEEE80211_NWID_LEN;
    if (ioctl(s, SIOCGIWESSID, &iwr) < 0) {
        errx(1, "unable to fetch ssid Something wrong __INVESTIGATE__\n");
    }

    close(s);
    return iwr.u.data.length;
}

static void
showatftable(const char *ifname, char *show_per_peer_table)
{
#define OTHER_SSID "Others   \0"
    int s,i;
    uint8_t *buf;
    uint8_t *sta_mac;
    struct iwreq iwr;
    struct atftable set_atp;
    int quotient_val = 0 ,remainder_val = 0;
    int quotient_cfg = 0 ,remainder_cfg = 0;
    const char *ntoa = NULL;
    u_int8_t ssid[IEEE80211_NWID_LEN+1];
    int ssid_length = 0;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
    }
    (void) memset(&set_atp, 0, sizeof(set_atp));
    set_atp.id_type = IEEE80211_IOCTL_ATF_SHOWATFTBL;
    if(show_per_peer_table){
        if(atoi(show_per_peer_table) != ATF_SHOW_PER_PEER_TABLE) {
            errx(1, "Invalid Showatftable argument\n");
            close(s);
            return;
        }else{
            set_atp.show_per_peer_table = atoi(show_per_peer_table);
        }
    }
    buf = ((uint8_t *) &set_atp);
    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        close(s);
        errx(1, "ifname too long: %s\n", ifname);
        return;
    }
    ssid_length = get_ssid(ifname,ssid); /*get current vap ssid */
    if(ssid_length < 0){
        errx(1, "unable to get_ssid");
        return;
    }

    ssid[ssid_length]='\0';
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_atp);
    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
            errx(1, "unable to set showatftable success");
    }

    if(set_atp.info_cnt) {
        if(set_atp.atf_group) {
            fprintf(stderr,"\n   GROUP            SSID/Client(MAC Address)         Air time(Percentage)        Config ATF(Percentage)      Assoc_Status(1-Assoc,0-No-Assoc)    All-token-used\n");
            } else {
                fprintf(stderr,"\n   SSID             Client(MAC Address)         Air time(Percentage)        Config ATF(Percentage)      Peer_Assoc_Status(1--Assoc,0-No-Assoc)    All-token-used\n");
            }

            for (i =0; i < set_atp.info_cnt; i++)
            {
                quotient_val = set_atp.atf_info[i].value/10;
                remainder_val = set_atp.atf_info[i].value%10;
                quotient_cfg = set_atp.atf_info[i].cfg_value/10;
                remainder_cfg = set_atp.atf_info[i].cfg_value%10;

                if( ((!strncmp(ssid,set_atp.atf_info[i].ssid, ssid_length ) && (strlen(set_atp.atf_info[i].ssid) == ssid_length)) || !strncmp("Others   ",set_atp.atf_info[i].ssid, strlen(OTHER_SSID))) || set_atp.atf_group)
                {
                    if(set_atp.atf_info[i].info_mark == 0)
                    {
                        if(set_atp.atf_group) {
                            fprintf(stderr,"   %s",set_atp.atf_info[i].grpname);
                        } else {
                            fprintf(stderr,"   %s",set_atp.atf_info[i].ssid);
                        }
                        fprintf(stderr,"                                            %d.%d",quotient_val,remainder_val);
                        if( set_atp.atf_info[i].cfg_value !=0)
                            fprintf(stderr,"                           %d.%d\n",quotient_cfg,remainder_cfg);
                        else
                            fprintf(stderr,"\n");
                    } else {
                        sta_mac = &(set_atp.atf_info[i].sta_mac[0]);
                        ntoa = ieee80211_ntoa(sta_mac);
                        if(set_atp.atf_group) {
                            fprintf(stderr,"                   %s / %s",set_atp.atf_info[i].ssid, (ntoa != NULL) ? ntoa:"WRONG MAC");
                        } else {
                             fprintf(stderr,"                     %s",(ntoa != NULL) ? ntoa:"WRONG MAC");
                        }
                        fprintf(stderr,"                   %d.%d",quotient_val,remainder_val);
                        fprintf(stderr,"                      %d.%d",quotient_cfg,remainder_cfg);
                        fprintf(stderr,"                                    %d\n",set_atp.atf_info[i].assoc_status);
                        fprintf(stderr,"   %d\n",set_atp.atf_info[i].all_tokens_used);
                    }

                    fprintf(stderr,"\n\n");
                }
            }
            if(set_atp.atf_status == 0) {
                fprintf(stderr,"\n   ATF IS DISABLED!!! The above ATF configuration will not have any effect.\n\n");
            }
        } else {
            fprintf(stderr,"   Air time table is empty\n");
        }
        fprintf(stderr,"ctl busy %d ext busy %d rf %d tf %d \n",
            (set_atp.busy & 0xff), (set_atp.busy & 0xff00) >> 8,
            (set_atp.busy & 0xff0000) >> 16, (set_atp.busy & 0xff000000) >> 24);

        close(s);
#undef OTHER_SSID
}

static void
showairtime(const char *ifname)
{
        int s,i;
        uint8_t *buf;
        uint8_t *sta_mac;
        struct iwreq iwr;
        struct atftable set_atp;
        const char *ntoa = NULL;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0){
            err(1, "socket(SOCK_DRAGM)");
        }

        (void) memset(&set_atp, 0, sizeof(set_atp));
        set_atp.id_type = IEEE80211_IOCTL_ATF_SHOWAIRTIME;
        buf = ((uint8_t *) &set_atp);
        (void) memset(&iwr, 0, sizeof(iwr));
        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(set_atp);
        if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
                errx(1, "unable to set showairtime success");
        }

        if(set_atp.info_cnt)
        {
           fprintf(stderr,"\n         Client(MAC Address)         Air time(Percentage 1000) \n");
           for (i =0; i < set_atp.info_cnt; i++)
           {
               if(set_atp.atf_info[i].info_mark == 1)
               {
                  sta_mac = &(set_atp.atf_info[i].sta_mac[0]);
                  ntoa = ieee80211_ntoa(sta_mac);

                  fprintf(stderr,"           %s",(ntoa != NULL) ? ntoa:"WRONG MAC");
                  fprintf(stderr,"                  %d \n",set_atp.atf_info[i].value);
               }
           }
           fprintf(stderr,"\n\n");
        }else{
            fprintf(stderr,"   Air time table is empty\n");
        }
        close(s);

}

static void flushatftable(const char *ifname)
{
    int s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addssid_val set_atp;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
        return;
    }

    (void) memset(&set_atp, 0, sizeof(set_atp));
    set_atp.id_type = IEEE80211_IOCTL_ATF_FLUSHTABLE;
    buf = ((uint8_t *) &set_atp);
    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_atp);
    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        errx(1, "Flush atf table failed");
    }
    close(s);
}

static void
set_addssid_pval(const char *ifname, char *ssid, char *val)
{
        int s, cnt = 0;
        uint8_t *buf;
        struct iwreq iwr;
        struct addssid_val  set_atp;

        cnt = strlen(val);
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0){
            err(1, "socket(SOCK_DRAGM)");
            fprintf(stderr,"\n Failed on open socket!!\n");
            return;
        }

        (void) memset(&set_atp, 0, sizeof(set_atp));
        memcpy(&(set_atp.ssid[0]),ssid,strlen(ssid));
        set_atp.id_type = IEEE80211_IOCTL_ATF_ADDSSID;
        if(cnt >3 )
        {
            fprintf(stderr,"\n Input percentage value out of range between 0 and 100!!\n");
            close(s);
            return;
        }
        while(cnt-- != 0)
        {
            if((*val >= '0')&&(*val <= '9'))
            {
                set_atp.value = set_atp.value*10 + (*val - '0');
                val++;
            }
            else{
                fprintf(stderr, " Input wong percentage value, its range is between 0 ~ 100\n");
                close(s);
                return;
            }
        }

       if(set_atp.value > 100)
       {
           fprintf(stderr,"Input percentage value is over 100!!");
           close(s);
           return;
       }

        set_atp.value = set_atp.value*10;
        buf = ((uint8_t *) &set_atp);
        (void) memset(&iwr, 0, sizeof(iwr));
        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(set_atp);

        if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
                errx(1, "unable to set ATP success");
                return;
        }
        close(s);
}

static void
set_delssid(const char *ifname, char *ssid)
{
        int s;
        uint8_t *buf;
        struct iwreq iwr;
        struct addssid_val  set_atp;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0){
            err(1, "socket(SOCK_DRAGM)");
            return;
        }

        (void) memset(&set_atp, 0, sizeof(set_atp));
        memcpy(&(set_atp.ssid[0]),ssid,strlen(ssid));
        set_atp.id_type = IEEE80211_IOCTL_ATF_DELSSID;
        buf = ((uint8_t *) &set_atp);
        (void) memset(&iwr, 0, sizeof(iwr));
        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(set_atp);
        if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
                errx(1, "unable to set DEL ATP success");
        }
        close(s);
}

static void
set_addsta_pval(const char *ifname, char *macaddr, char *val, char *ssid)
{
        int s, cnt = 0;
        uint8_t *buf;
        struct iwreq iwr;
        struct addsta_val  set_sta;
        uint8_t i,len = 0;
        uint8_t lbyte = 0, ubyte = 0;
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0){
            err(1, "socket(SOCK_DRAGM)");
            return;
        }
        cnt = strlen(val);
        (void) memset(&set_sta, 0, sizeof(set_sta));
        if(ssid)
            memcpy(&(set_sta.ssid[0]), ssid, strlen(ssid));
        len = strlen(macaddr);
        if((len != 2*IEEE80211_ADDR_LEN )||(cnt == 0))
        {
            err(1,"\n Unable to set ADD_STA success,failed on wrong mac ddress length or format(example: 24aa450067fe)\n");
            return;
        }

        for (i = 0; i < len; i += 2) {
            if ((macaddr[i] >= '0') && (macaddr[i] <= '9'))  {
                 ubyte = macaddr[i] - '0';
            } else if ((macaddr[i] >= 'A') && (macaddr[i] <= 'F')) {
                 ubyte = macaddr[i] - 'A' + 10;
            } else if ((macaddr[i] >= 'a') && (macaddr[i] <= 'f')) {
                 ubyte = macaddr[i] - 'a' + 10;
            }

            if ((macaddr[i + 1] >= '0') && (macaddr[i + 1] <= '9'))  {
                 lbyte = macaddr[i + 1] - '0';
            } else if ((macaddr[i + 1] >= 'A') && (macaddr[i + 1] <= 'F')) {
                 lbyte = macaddr[i + 1] - 'A' + 10;
            } else if ((macaddr[i + 1] >= 'a') && (macaddr[i + 1] <= 'f')) {
                 lbyte = macaddr[i + 1] - 'a' + 10;
            }

            set_sta.sta_mac[i/2] = (ubyte << 4) | lbyte;
        }

        if(cnt >3 )
        {
            err(1,"\n Input percentage value out of range between 0 and 100!!\n");
            return;
        }

        while(cnt-- != 0)
        {
            if((*val >= '0')&&(*val <= '9'))
            {
                set_sta.value = set_sta.value*10 + (*val - '0');
                val++;
            }
            else{
                err(1, "\n Input wong percentage value, its range is between 0 ~ 100\n");
                return;
            }
        }

       if(set_sta.value > 100)
       {
           fprintf(stderr,"Input percentage value is over 100!!");
           close(s);
           return;
       }

        set_sta.value = set_sta.value * ATF_AIRTIME_CONVERSION_FACTOR;
        set_sta.id_type = IEEE80211_IOCTL_ATF_ADDSTA;
        buf = ((uint8_t *) &set_sta);
        (void) memset(&iwr, 0, sizeof(iwr));
        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(set_sta);
        if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
                errx(1, "unable to set ADD_STA success");
        }
        close(s);
}

static void
set_delsta(const char *ifname, char *macaddr)
{
        int s;
        uint8_t *buf;
        struct iwreq iwr;
        struct addsta_val  set_sta;
        uint8_t i,len = 0;
        uint8_t lbyte = 0, ubyte = 0;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0){
            err(1, "socket(SOCK_DRAGM)");
            return;
        }

        (void) memset(&set_sta, 0, sizeof(set_sta));
        len = strlen(macaddr);
        if(len != 2*IEEE80211_ADDR_LEN )
        {
            errx(1, "unable to set DEL_STA success,failed on wrong mac ddress length");
            return;
        }

        for (i = 0; i < len; i += 2) {
            if ((macaddr[i] >= '0') && (macaddr[i] <= '9'))  {
                 ubyte = macaddr[i] - '0';
            } else if ((macaddr[i] >= 'A') && (macaddr[i] <= 'F')) {
                 ubyte = macaddr[i] - 'A' + 10;
            } else if ((macaddr[i] >= 'a') && (macaddr[i] <= 'f')) {
                 ubyte = macaddr[i] - 'a' + 10;
            }

            if ((macaddr[i + 1] >= '0') && (macaddr[i + 1] <= '9'))  {
                 lbyte = macaddr[i + 1] - '0';
            } else if ((macaddr[i + 1] >= 'A') && (macaddr[i + 1] <= 'F')) {
                 lbyte = macaddr[i + 1] - 'A' + 10;
            } else if ((macaddr[i + 1] >= 'a') && (macaddr[i + 1] <= 'f')) {
                 lbyte = macaddr[i + 1] - 'a' + 10;
            }

            set_sta.sta_mac[i/2] = (ubyte << 4) | lbyte;
        }

        set_sta.id_type = IEEE80211_IOCTL_ATF_DELSTA;
        buf = ((uint8_t *) &set_sta);
        (void) memset(&iwr, 0, sizeof(iwr));
        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(set_sta);
        if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
                errx(1, "unable to set DEL_STA success");
        }
        close(s);
}

static void set_addatfgroup(const char *ifname, char *groupname, char *ssid)
{
    int32_t s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addgroup_val set_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
        printf("\n Failed on open socket!!\n");
        return;
    }

    (void)memset(&set_group, 0, sizeof(set_group) );
    memcpy( &set_group.name[0], groupname, strlen(groupname) );
    memcpy( &set_group.ssid[0], ssid, strlen(ssid) );
    set_group.id_type = IEEE80211_IOCTL_ATF_ADDGROUP;

    buf = ((uint8_t *)&set_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        errx(1, "unable to set ATP success");
    }
    close(s);
    return;
}

static void set_configatfgroup(const char *ifname, char *groupname, char *val)
{
    int32_t s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addgroup_val config_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
        printf("\n Failed on open socket!!\n");
        return;
    }

    if(atoi(val) <= 0 || atoi(val) > 100) {
        errx(1, "Invalid Airtime input.");
        close(s);
        return;
    }

    (void) memset(&config_group, 0, sizeof(config_group));
    memcpy(&config_group.name[0], groupname, strlen(groupname));

    config_group.id_type = IEEE80211_IOCTL_ATF_CONFIGGROUP;
    config_group.value = atoi(val);

    config_group.value = config_group.value * 10;
    buf = ((uint8_t *) &config_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(config_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        errx(1, "unable to set ATP success");
    }
    close(s);
    return;
}

static void set_delatfgroup(const char *ifname, char *groupname)
{
    int32_t s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addgroup_val del_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
        printf("\n Failed on open socket!!\n");
        return;
    }

    (void) memset(&del_group, 0, sizeof(del_group));

    memcpy(&del_group.name[0], groupname, strlen(groupname));
    del_group.id_type = IEEE80211_IOCTL_ATF_DELGROUP;

    buf = ((uint8_t *) &del_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(del_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        errx(1, "unable to set ATP success");
    }
    close(s);
    return;
}

static void showatfgroup(const char *ifname)
{
    int32_t s;
    uint8_t *buf;
    int32_t i = 0, j=0;
    struct iwreq iwr;
    struct atfgrouptable list_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        err(1, "socket(SOCK_DRAGM)");
        printf("\n Failed on open socket!!\n");
        return;
    }

    (void) memset(&list_group, 0, sizeof(list_group));
    list_group.id_type = IEEE80211_IOCTL_ATF_SHOWGROUP;

    buf = ((uint8_t *) &list_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return;
    }
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(list_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        errx(1, "unable to set ATP success");
        close(s);
        return;
    }
    close(s);

    if(list_group.info_cnt)
    {
        fprintf(stderr,"\n          Group           Airtime         SSID List    \n");
        for (i =0; i < list_group.info_cnt; i++)
        {
            fprintf(stderr,"          %s", list_group.atf_groups[i].grpname);
            fprintf(stderr,"            %d", list_group.atf_groups[i].grp_cfg_value);
            fprintf(stderr,"           ");
            for(j=0; j<list_group.atf_groups[i].grp_num_ssid; j++)
            {
                fprintf(stderr,"%s ", list_group.atf_groups[i].grp_ssid[j]);
            }
            fprintf(stderr,"\n");
        }
        fprintf(stderr,"\n\n");
    } else {
        fprintf(stderr,"   Air time table is empty\n");
    }

}

static int atf_addsta_tput(const char *ifname, char *macaddr, char *val, char *val2)
{
    int s, i;
    struct iwreq iwr;
    struct addsta_val set_sta;
    uint8_t len, cnt, cnt2;
    uint8_t lbyte = 0, ubyte = 0, non_zero, wild_card, value;
    uint8_t mac[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("socket error\n");
        return 1;
    }

    cnt = strlen(val);
    cnt2 = val2 ? strlen(val2) : 0;
    len = strlen(macaddr);
    memset(&set_sta, 0, sizeof(set_sta));

    if ((len != 2 * IEEE80211_ADDR_LEN) || (cnt == 0)) {
        printf("invalid mac address (eg:aabbcc112233) or invalid throughput\n");
        close(s);
        return 1;
    }

    non_zero = 0;
    for (i = 0; i < len; i += 2) {
        if ((macaddr[i] >= '0') && (macaddr[i] <= '9'))  {
             ubyte = macaddr[i] - '0';
        } else if ((macaddr[i] >= 'A') && (macaddr[i] <= 'F')) {
             ubyte = macaddr[i] - 'A' + 10;
        } else if ((macaddr[i] >= 'a') && (macaddr[i] <= 'f')) {
             ubyte = macaddr[i] - 'a' + 10;
        }

        if ((macaddr[i + 1] >= '0') && (macaddr[i + 1] <= '9'))  {
             lbyte = macaddr[i + 1] - '0';
        } else if ((macaddr[i + 1] >= 'A') && (macaddr[i + 1] <= 'F')) {
             lbyte = macaddr[i + 1] - 'A' + 10;
        } else if ((macaddr[i + 1] >= 'a') && (macaddr[i + 1] <= 'f')) {
             lbyte = macaddr[i + 1] - 'a' + 10;
        }

        set_sta.sta_mac[i / 2] = (ubyte << 4) | lbyte;

        if (set_sta.sta_mac[i / 2])
            non_zero = 1;
    }

    if (!non_zero) {
        printf("invalid mac address\n");
        close(s);
        return 1;
    }

    while (cnt--) {
        if ((*val >= '0') && (*val <= '9')) {
            set_sta.value = set_sta.value * 10 + (*val - '0');
            val++;
        } else {
            printf("invalid char in throughput\n");
            close(s);
            return 1;
        }
    }

    value = 0;
    if (cnt2) {
        while (cnt2--) {
            if ((*val2 >= '0') && (*val2 <= '9')) {
                value = value * 10 + (*val2 - '0');
                val2++;
            } else {
                printf("invalid char in airtime\n");
                close(s);
                return 1;
            }
        }
    }

    wild_card = 1;
    for (i = 0; i < IEEE80211_ADDR_LEN; i++) {
        if (set_sta.sta_mac[i] != 0xFF) {
            wild_card = 0;
            break;
        }
    }
    if (wild_card)
        set_sta.value = 1300000;

    if (!set_sta.value || set_sta.value > 1300000) {
        printf("invalid throughput\n");
        close(s);
        return 1;
    }

    if (!value || value > 100) {
        value = 100;
    }

    set_sta.value &= ATF_TPUT_MASK;
    set_sta.value |= (value << ATF_AIRTIME_SHIFT) & ATF_AIRTIME_MASK;

    set_sta.id_type = IEEE80211_IOCTL_ATF_ADDSTA_TPUT;
    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return 1;
    }
    iwr.u.data.pointer = (void *)&set_sta;
    iwr.u.data.length = sizeof(set_sta);

    if (ioctl(s, IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        printf("unable to set throughput requirement\n");
        close(s);
        return 1;
    }

    close(s);
    return 0;
}

static int atf_delsta_tput(const char *ifname, char *macaddr)
{
    int s, i;
    struct iwreq iwr;
    struct addsta_val set_sta;
    uint8_t len;
    uint8_t lbyte = 0, ubyte = 0, non_zero;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("socket error\n");
        return 1;
    }

    len = strlen(macaddr);
    memset(&set_sta, 0, sizeof(set_sta));

    if (len != 2 * IEEE80211_ADDR_LEN) {
        printf("invalid mac address (eg:aabbcc112233)\n");
        close(s);
        return 1;
    }

    non_zero = 0;
    for (i = 0; i < len; i += 2) {
        if ((macaddr[i] >= '0') && (macaddr[i] <= '9'))  {
             ubyte = macaddr[i] - '0';
        } else if ((macaddr[i] >= 'A') && (macaddr[i] <= 'F')) {
             ubyte = macaddr[i] - 'A' + 10;
        } else if ((macaddr[i] >= 'a') && (macaddr[i] <= 'f')) {
             ubyte = macaddr[i] - 'a' + 10;
        }

        if ((macaddr[i + 1] >= '0') && (macaddr[i + 1] <= '9'))  {
             lbyte = macaddr[i + 1] - '0';
        } else if ((macaddr[i + 1] >= 'A') && (macaddr[i + 1] <= 'F')) {
             lbyte = macaddr[i + 1] - 'A' + 10;
        } else if ((macaddr[i + 1] >= 'a') && (macaddr[i + 1] <= 'f')) {
             lbyte = macaddr[i + 1] - 'a' + 10;
        }

        set_sta.sta_mac[i / 2] = (ubyte << 4) | lbyte;

        if (set_sta.sta_mac[i / 2])
            non_zero = 1;
    }

    if (!non_zero) {
        printf("invalid mac address\n");
        close(s);
        return 1;
    }

    set_sta.id_type = IEEE80211_IOCTL_ATF_DELSTA_TPUT;
    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return 1;
    }
    iwr.u.data.pointer = (void *)&set_sta;
    iwr.u.data.length = sizeof(set_sta);

    if (ioctl(s, IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        printf("unable to un-set throughput requirement\n");
        close(s);
        return 1;
    }

    close(s);
    return 0;
}

static int atf_show_tput(const char *ifname)
{
    int s;
    struct iwreq iwr;
    struct addsta_val set_sta;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("socket error\n");
        return 1;
    }

    set_sta.id_type = IEEE80211_IOCTL_ATF_SHOW_TPUT;
    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return 1;
    }
    iwr.u.data.pointer = (void *)&set_sta;
    iwr.u.data.length = sizeof(set_sta);

    if (ioctl(s, IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        printf("unable to dump throughput table\n");
        close(s);
        return 1;
    }

    close(s);
    return 0;
}
#endif

static int atf_show_stat(const char *ifname, char *macaddr)
{
    int s, i;
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;
    uint8_t len, lbyte, ubyte;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("socket error\n");
        return 1;
    }

    memset(&config, 0, sizeof(config));
    config.cmdtype = IEEE80211_PARAM_STA_ATF_STAT;
    len = strlen(macaddr);
    for (i = 0; i < len; i += 2) {
        lbyte = ubyte = 0;

        if ((macaddr[i] >= '0') && (macaddr[i] <= '9'))  {
             ubyte = macaddr[i] - '0';
        } else if ((macaddr[i] >= 'A') && (macaddr[i] <= 'F')) {
             ubyte = macaddr[i] - 'A' + 10;
        } else if ((macaddr[i] >= 'a') && (macaddr[i] <= 'f')) {
             ubyte = macaddr[i] - 'a' + 10;
        }

        if ((macaddr[i + 1] >= '0') && (macaddr[i + 1] <= '9'))  {
             lbyte = macaddr[i + 1] - '0';
        } else if ((macaddr[i + 1] >= 'A') && (macaddr[i + 1] <= 'F')) {
             lbyte = macaddr[i + 1] - 'A' + 10;
        } else if ((macaddr[i + 1] >= 'a') && (macaddr[i + 1] <= 'f')) {
             lbyte = macaddr[i + 1] - 'a' + 10;
        }

        config.data.atf.macaddr[i / 2] = (ubyte << 4) | lbyte;
    }
    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return 1;
    }
    iwr.u.data.pointer = (void *)&config;
    iwr.u.data.length = sizeof(config);

    if (ioctl(s, IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        printf("unable to get stats\n");
        close(s);
        return 1;
    }

    fprintf(stderr, "Short Average %d, Total Used Tokens %llu\n",
            config.data.atf.short_avg, config.data.atf.total_used_tokens);

    close(s);
    return 0;
}

/* ps_activity: power save activity */
#define LIST_STATION_ALLOC_SIZE 24*1024
static void
list_stations(const char *ifname, int ps_activity)
{
    char *ieee80211_phymode_str[23] =  {
        "IEEE80211_MODE_AUTO",
        "IEEE80211_MODE_11A",
        "IEEE80211_MODE_11B",
        "IEEE80211_MODE_11G",
        "IEEE80211_MODE_FH",
        "IEEE80211_MODE_TURBO_A",
        "IEEE80211_MODE_TURBO_G",
        "IEEE80211_MODE_11NA_HT20",
        "IEEE80211_MODE_11NG_HT20",
        "IEEE80211_MODE_11NA_HT40PLUS",
        "IEEE80211_MODE_11NA_HT40MINUS",
        "IEEE80211_MODE_11NG_HT40PLUS",
        "IEEE80211_MODE_11NG_HT40MINUS",
        "IEEE80211_MODE_11NG_HT40",
        "IEEE80211_MODE_11NA_HT40",
        "IEEE80211_MODE_11AC_VHT20",
        "IEEE80211_MODE_11AC_VHT40PLUS",
        "IEEE80211_MODE_11AC_VHT40MINUS",
        "IEEE80211_MODE_11AC_VHT40",
        "IEEE80211_MODE_11AC_VHT80",
        "IEEE80211_MODE_11AC_VHT160",
        "IEEE80211_MODE_11AC_VHT80_80",
        (char *)NULL,
    };

    uint8_t *buf;
    struct iwreq iwr;
    uint8_t *cp;
    int s;
    u_int32_t txrate, rxrate = 0, maxrate = 0;
    u_int32_t time_val=0, hour_val=0, min_val=0, sec_val=0;
    const char *ntoa = NULL;
    int req_space = 0;
    u_int64_t len = 0;

	buf = malloc(LIST_STATION_ALLOC_SIZE);
	if(!buf) {
	  fprintf (stderr, "Unable to allocate memory for station list\n");
	  return;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		free(buf);
		err(1, "socket(SOCK_DRAGM)");
	}

	if (!strncmp(ifname, "wifi", 4)) {
		free(buf);
		err(1, "Not a valid interface");
	}

	(void) memset(&iwr, 0, sizeof(iwr));
	if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
		fprintf(stderr, "ifname too long: %s\n", ifname);
                close(s);
		free(buf);
		return;
	}
	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = LIST_STATION_ALLOC_SIZE;

    iwr.u.data.flags = 0;
    //Support for 512 client
    req_space = ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr);
	if (req_space < 0 ){
		free(buf);
		errx(1, "unable to get station information");
    }
    else if(req_space > 0) {
        free(buf);
        buf = malloc(req_space);
        if(!buf) {
            fprintf (stderr, "Unable to allocate memory for station list\n");
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = req_space;
        if(iwr.u.data.length < req_space)
            iwr.u.data.flags = 1;
        if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0 ){
            free(buf);
            errx(1, "unable to get station information");
        }
        len = req_space;

    }
    else {
        len = iwr.u.data.length;
    }

    if (len < sizeof(struct ieee80211req_sta_info)){
        free(buf);
        close(s);
        return;
    }
	cp = buf;
        if (ps_activity == 0)
	{
		printf("%-17.17s %4s %4s %4s %4s %4s %7s %7s %4s %6s %6s %5s %12s %7s %8s %14s %6s %9s %6s %6s %24s\n"
		, "ADDR"
		, "AID"
		, "CHAN"
		, "TXRATE"
		, "RXRATE"
		, "RSSI"
        , "MINRSSI"
        , "MAXRSSI"
		, "IDLE"
		, "TXSEQ"
		, "RXSEQ"
		, "CAPS"
	    , "ACAPS"
		, "ERP"
		, "STATE"
        , "MAXRATE(DOT11)"
	    , "HTCAPS"
		, "ASSOCTIME"
		, "IEs"
	    , "MODE"
		, "PSMODE"
		);
	}
	if (ps_activity == 1)
	{
		printf("%-17.17s %4s %4s %4s %4s %4s %7s %7s %4s %6s %6s %5s %12s %7s %8s %14s %6s %9s %6s %6s %24s %6s %9s\n"
		, "ADDR"
		, "AID"
		, "CHAN"
		, "TXRATE"
		, "RXRATE"
		, "RSSI"
		, "MINRSSI"
		, "MAXRSSI"
		, "IDLE"
		, "TXSEQ"
		, "RXSEQ"
		, "CAPS"
		, "ACAPS"
		, "ERP"
		, "STATE"
		, "MAXRATE(DOT11)"
		, "HTCAPS"
		, "ASSOCTIME"
		, "IEs"
		, "MODE"
		, "PSMODE"
		, "PSTIME"
		, "AWAKETIME"
		);
	}
	cp = buf;
	do {
		struct ieee80211req_sta_info *si;
		uint8_t *vp;

		si = (struct ieee80211req_sta_info *) cp;
		time_val = si->isi_tr069_assoc_time.tv_sec;
	 	hour_val = time_val / 3600;
 	 	time_val = time_val % 3600;
 	 	min_val = time_val / 60;
 	 	sec_val = time_val % 60;
		vp = (u_int8_t *)(si+1);
        if(si->isi_txratekbps == 0)
           txrate = (si->isi_rates[si->isi_txrate] & IEEE80211_RATE_VAL)/2;
        else
            txrate = si->isi_txratekbps / 1000;
        if(si->isi_rxratekbps >= 0) {
            rxrate = si->isi_rxratekbps / 1000;
		}

        maxrate = si->isi_maxrate_per_client;

        if (maxrate & 0x80) maxrate &= 0x7f;
                ntoa = ieee80211_ntoa(si->isi_macaddr);
		printf("%s %4u %4d %3dM %6dM %4d %7d %7d %4d %6d %7d %5.4s %-5.5s %3x %10x %14d %15.6s %02u:%02u:%02u    "
			, (ntoa != NULL) ? ntoa:"WRONG MAC"
			, IEEE80211_AID(si->isi_associd)
			, ieee80211_mhz2ieee(si->isi_freq)
			, txrate
			, rxrate
			, si->isi_rssi
            , si->isi_min_rssi
            , si->isi_max_rssi
			, si->isi_inact
			, si->isi_txseqs[0]
			, si->isi_rxseqs[0]
		    , getcaps(si->isi_capinfo)
		    , getathcaps(si->isi_athflags)
			, si->isi_erp
			, si->isi_state
            , maxrate
		    , gethtcaps(si->isi_htcap)
			, hour_val
			, min_val
			, sec_val
		);
		printies(vp, si->isi_ie_len, 24);
		printf (" %s ",(si->isi_stamode < 22)?ieee80211_phymode_str[si->isi_stamode]:"IEEE80211_MODE_11B");
		if (ps_activity == 0)
		{
			printf("%3d \r\n",si->isi_ps);
		}
		else if (ps_activity == 1)
			printf(" %d %6d %9d\r\n",si->isi_ps, si->ps_time, si->awake_time);
		cp += si->isi_len, len -= si->isi_len;
	} while (len >= sizeof(struct ieee80211req_sta_info));

	free(buf);
        close(s);
}

static void
list_stations_human_format(const char *ifname)
{
    char *ieee80211_phymode_str[23] =  {
        "IEEE80211_MODE_AUTO",
        "IEEE80211_MODE_11A",
        "IEEE80211_MODE_11B",
        "IEEE80211_MODE_11G",
        "IEEE80211_MODE_FH",
        "IEEE80211_MODE_TURBO_A",
        "IEEE80211_MODE_TURBO_G",
        "IEEE80211_MODE_11NA_HT20",
        "IEEE80211_MODE_11NG_HT20",
        "IEEE80211_MODE_11NA_HT40PLUS",
        "IEEE80211_MODE_11NA_HT40MINUS",
        "IEEE80211_MODE_11NG_HT40PLUS",
        "IEEE80211_MODE_11NG_HT40MINUS",
        "IEEE80211_MODE_11NG_HT40",
        "IEEE80211_MODE_11NA_HT40",
        "IEEE80211_MODE_11AC_VHT20",
        "IEEE80211_MODE_11AC_VHT40PLUS",
        "IEEE80211_MODE_11AC_VHT40MINUS",
        "IEEE80211_MODE_11AC_VHT40",
        "IEEE80211_MODE_11AC_VHT80",
        "IEEE80211_MODE_11AC_VHT160",
        "IEEE80211_MODE_11AC_VHT80_80",
        (char *)NULL,
    };


	uint8_t *buf;
	struct iwreq iwr;
	uint8_t *cp;
	int s, k=0;
    u_int64_t len = 0;
    u_int32_t txrate, rxrate = 0, maxrate = 0;
	u_int32_t time_val=0, hour_val=0, min_val=0, sec_val=0;
    const char *ntoa = NULL;
	buf = malloc(LIST_STATION_ALLOC_SIZE);
	if(!buf) {
	  fprintf (stderr, "Unable to allocate memory for station list\n");
	  return;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		free(buf);
		err(1, "socket(SOCK_DRAGM)");
	}

	if (!strncmp(ifname, "wifi", 4)) {
		free(buf);
		err(1, "Not a valid interface");
	}

	(void) memset(&iwr, 0, sizeof(iwr));
	if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
		fprintf(stderr, "ifname too long: %s\n", ifname);
		free(buf);
		close(s);
		return;
	}
	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = LIST_STATION_ALLOC_SIZE;
    iwr.u.data.flags = 0;
    //Support for 512 client
    int req_space = ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr);
	if (req_space < 0 ){
		free(buf);
		errx(1, "unable to get station information");
    }
    else if(req_space > 0) {
        free(buf);
        buf = malloc(req_space);
        if(!buf) {
            fprintf (stderr, "Unable to allocate memory for station list\n");
            close(s);
            return;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = req_space;
        if(iwr.u.data.length < req_space)
            iwr.u.data.flags = 1;
        if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0 ){
            free(buf);
            errx(1, "unable to get station information");
        }
        len = req_space;

    }
    else {
        len = iwr.u.data.length;
    }

    if (len < sizeof(struct ieee80211req_sta_info)){
        free(buf);
        close(s);
        return;
    }
	cp = buf;

	do {
		struct ieee80211req_sta_info *si;
		uint8_t *vp;

		si = (struct ieee80211req_sta_info *) cp;
		time_val = si->isi_tr069_assoc_time.tv_sec;
	 	hour_val = time_val / 3600;
 	 	time_val = time_val % 3600;
 	 	min_val = time_val / 60;
 	 	sec_val = time_val % 60;
		vp = (u_int8_t *)(si+1);
        if(si->isi_txratekbps == 0)
           txrate = (si->isi_rates[si->isi_txrate] & IEEE80211_RATE_VAL)/2;
        else
            txrate = si->isi_txratekbps / 1000;
        if(si->isi_rxratekbps >= 0) {
            rxrate = si->isi_rxratekbps / 1000;
		}

        maxrate = si->isi_maxrate_per_client;

        if (maxrate & 0x80) maxrate &= 0x7f;
                ntoa = ieee80211_ntoa(si->isi_macaddr);
		printf("ADDR :%s AID:%4u CHAN:%4d TXRATE:%3dM RXRATE:%6dM RSSI:%4d IDLE:%4d TXSEQ:%6d RXSEQ:%7d CAPS:%5.4s ACAPS:%-5.5s ERP:%3x STATE:%10x MAXRATE(DOT11):%14d HTCAPS:%14.6s ASSOCTIME:%02u:%02u:%02u"
			, (ntoa != NULL) ? ntoa:"WRONG MAC"
			, IEEE80211_AID(si->isi_associd)
			, ieee80211_mhz2ieee(si->isi_freq)
			, txrate
			, rxrate
			, si->isi_rssi
			, si->isi_inact
			, si->isi_txseqs[0]
			, si->isi_rxseqs[0]
		    , getcaps(si->isi_capinfo)
		    , getathcaps(si->isi_athflags)
			, si->isi_erp
			, si->isi_state
            , maxrate
		    , gethtcaps(si->isi_htcap)
			, hour_val
			, min_val
			, sec_val
		);
		printies(vp, si->isi_ie_len, 24);
		printf (" MODE: %s \r\n",(si->isi_stamode < 22)?ieee80211_phymode_str[si->isi_stamode]:"IEEE80211_MODE_11B");
		printf("  PSMODE: %d \r\n",si->isi_ps);
        cp += si->isi_len, len -= si->isi_len;
	} while (len >= sizeof(struct ieee80211req_sta_info));

	free(buf);
        close(s);
}

/* unalligned little endian access */
#ifndef LE_READ_4
#define LE_READ_4(p)					\
	((u_int32_t)					\
	 ((((const u_int8_t *)(p))[0]      ) |		\
	  (((const u_int8_t *)(p))[1] <<  8) |		\
	  (((const u_int8_t *)(p))[2] << 16) |		\
	  (((const u_int8_t *)(p))[3] << 24)))
#endif
static void
list_scan(const char *ifname)
{
	uint8_t buf[24*1024];
	struct iwreq iwr;
	char ssid[14];
	uint8_t *cp;
	int len;

	len = get80211priv(ifname, IEEE80211_IOCTL_SCAN_RESULTS,
			    buf, sizeof(buf));
	if (len == -1)
		errx(1, "unable to get scan results");
	if (len < sizeof(struct ieee80211req_scan_result))
		return;

	printf("%-14.14s  %-17.17s  %4s %4s  %-5s %3s %4s\n"
		, "SSID"
		, "BSSID"
		, "CHAN"
		, "RATE"
		, "S:N"
		, "INT"
		, "CAPS"
	);
	cp = buf;
	do {
		struct ieee80211req_scan_result *sr;
		uint8_t *vp;
        const char *ntoa;

		sr = (struct ieee80211req_scan_result *) cp;
		vp = (u_int8_t *)(sr+1);
                ntoa = ieee80211_ntoa(sr->isr_bssid);
		printf("%-14.*s  %s  %3d  %3dM %2d:%-2d  %3d %-4.4s"
			, copy_essid(ssid, sizeof(ssid), vp, sr->isr_ssid_len)
				, ssid
			, (ntoa != NULL) ? ntoa:"WRONG MAC"
			, ieee80211_mhz2ieee(sr->isr_freq)
			, getmaxrate(sr->isr_rates, sr->isr_nrates)
			, (int8_t) sr->isr_rssi, sr->isr_noise
			, sr->isr_intval
			, getcaps(sr->isr_capinfo)
		);
		printies(vp + sr->isr_ssid_len, sr->isr_ie_len, 24);;
		printf("\n");
		cp += sr->isr_len, len -= sr->isr_len;
	} while (len >= sizeof(struct ieee80211req_scan_result));
}

static void
print_chaninfo(const struct ieee80211_channel *c, const struct ieee80211_channel *c_160)
{
    char buf[50];
    char buf1[4];

    buf[0] = '\0';
    if (IEEE80211_IS_CHAN_FHSS(c))
        strlcat(buf, " FHSS", sizeof(buf));
    if (IEEE80211_IS_CHAN_11NA(c))
        strlcat(buf, " 11na", sizeof(buf));
    else if (IEEE80211_IS_CHAN_A(c))
        strlcat(buf, " 11a", sizeof(buf));
    else if (IEEE80211_IS_CHAN_11NG(c))
        strlcat(buf, " 11ng", sizeof(buf));
    /* XXX 11g schizophrenia */
    else if (IEEE80211_IS_CHAN_G(c) || IEEE80211_IS_CHAN_PUREG(c))
        strlcat(buf, " 11g", sizeof(buf));
    else if (IEEE80211_IS_CHAN_B(c))
        strlcat(buf, " 11b", sizeof(buf));
    if (IEEE80211_IS_CHAN_TURBO(c))
        strlcat(buf, " Turbo", sizeof(buf));
    if(IEEE80211_IS_CHAN_11N_CTL_CAPABLE(c))
        strlcat(buf, " C", sizeof(buf));
    if(IEEE80211_IS_CHAN_11N_CTL_U_CAPABLE(c))
        strlcat(buf, " CU", sizeof(buf));
    if(IEEE80211_IS_CHAN_11N_CTL_L_CAPABLE(c))
        strlcat(buf, " CL", sizeof(buf));
    if(IEEE80211_IS_CHAN_11AC_VHT20(c))
        strlcat(buf, " V", sizeof(buf));
    if(IEEE80211_IS_CHAN_11AC_VHT40PLUS(c))
        strlcat(buf, " VU", sizeof(buf));
    if(IEEE80211_IS_CHAN_11AC_VHT40MINUS(c))
        strlcat(buf, " VL", sizeof(buf));
    if(IEEE80211_IS_CHAN_11AC_VHT80(c)) {
        strlcat(buf, " V80-", sizeof(buf));
        snprintf(buf1, sizeof(buf1), "%3u", c->ic_vhtop_ch_freq_seg1);
        strlcat(buf, buf1, sizeof(buf));
    }
    if(IEEE80211_IS_CHAN_11AC_VHT160(c_160)) {
        strlcat(buf, " V160-", sizeof(buf));
        snprintf(buf1, sizeof(buf1), "%3u", c_160->ic_vhtop_ch_freq_seg2);
        strlcat(buf, buf1, sizeof(buf));
    }

    printf("Channel %3u : %u%c%c%c Mhz%-50.50s",
	    ieee80211_mhz2ieee(c->ic_freq), c->ic_freq,
	    IEEE80211_IS_CHAN_HALF(c) ? 'H' : (IEEE80211_IS_CHAN_QUARTER(c) ? 'Q' :  ' '),
	    IEEE80211_IS_CHAN_PASSIVE(c) ? '*' : ' ',IEEE80211_IS_CHAN_DFSFLAG(c) ?'~':' ', buf);
}

static void
list_channels(const char *ifname, int allchans)
{
    /* seg1 in ieee80211_channel structure is common to both 80 Mhz and 160 Mhz,
       hence we use a separate call to retrieve 160 Mhz information */
    struct ieee80211req_chaninfo chans = {0}, chans_160 = {0};
    struct ieee80211req_chaninfo achans = {0}, achans_160 = {0};
    const struct ieee80211_channel *c;
    const struct ieee80211_channel *c_160;
    int i, half;
    struct iwreq iwr;
    struct ieee80211_wlanconfig *config;

    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return;
    }
    config = (struct ieee80211_wlanconfig *)&chans_160;
    memset(config, 0, sizeof(*config));
    config->cmdtype = IEEE80211_WLANCONFIG_GETCHANINFO_160;
    iwr.u.data.pointer = (void *) &chans_160;
    iwr.u.data.length = sizeof(chans_160);

    if (get80211priv(ifname, IEEE80211_IOCTL_GETCHANINFO, &chans, sizeof(chans)) < 0)
		errx(1, "unable to get channel information");

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed");
        return;
    }
	if (!allchans) {
		struct ieee80211req_chanlist active = {0};

		if (get80211priv(ifname, IEEE80211_IOCTL_GETCHANLIST, &active, sizeof(active)) < 0)
			errx(1, "unable to get active channel list");
        memset(&achans, 0, sizeof(achans));
        memset(&achans_160, 0, sizeof(achans_160));
        for (i = 0; i < chans.ic_nchans; i++) {
            c = &chans.ic_chans[i];
            if (isset(active.ic_channels, ieee80211_mhz2ieee(c->ic_freq)) || allchans)
                achans.ic_chans[achans.ic_nchans++] = *c;
            c_160 = &chans_160.ic_chans[i];
            if (isset(active.ic_channels, ieee80211_mhz2ieee(c_160->ic_freq)) || allchans)
                achans_160.ic_chans[achans_160.ic_nchans++] = *c_160;
		}
	} else
        achans = chans;
        achans_160 = chans_160;
    half = achans.ic_nchans / 2;
    if (achans.ic_nchans % 2)
		half++;
    for (i = 0; i < achans.ic_nchans / 2; i++) {
        print_chaninfo(&achans.ic_chans[i], &achans_160.ic_chans[i]);
        print_chaninfo(&achans.ic_chans[half+i], &achans_160.ic_chans[half+i]);
		printf("\n");
	}
    if (achans.ic_nchans % 2) {
        print_chaninfo(&achans.ic_chans[i],&achans_160.ic_chans[i]);
		printf("\n");
	}

}

static void
list_keys(const char *ifname)
{
}

#define	IEEE80211_C_BITS \
"\020\1WEP\2TKIP\3AES\4AES_CCM\6CKIP\7FF\10TURBOP\11IBSS\12PMGT\13HOSTAP\14AHDEMO" \
"\15SWRETRY\16TXPMGT\17SHSLOT\20SHPREAMBLE\21MONITOR\22TKIPMIC\30WPA1" \
"\31WPA2\32BURST\33WME"

/*
 * Print a value a la the %b format of the kernel's printf
 */
void
printb(const char *s, unsigned v, const char *bits)
{
	int i, any = 0;
	char c;

    if(!bits) {
		printf("%s=%x", s, v);
        return;
    }

	if (*bits == 8)
		printf("%s=%o", s, v);
	else
		printf("%s=%x", s, v);
	bits++;
	putchar('<');

	while ((i = *bits++) != '\0') {
		if (v & (1 << (i-1))) {
			if (any)
				putchar(',');
			any = 1;
			for (; (c = *bits) > 32; bits++)
				putchar(c);
		} else
			for (; *bits > 32; bits++)
				;
	}
	putchar('>');
}

static void
list_capabilities(const char *ifname)
{
	u_int32_t caps;

	if (get80211param(ifname, IEEE80211_PARAM_DRIVER_CAPS, &caps, sizeof(caps)) < 0)
		errx(1, "unable to get driver capabilities");
	printb(ifname, caps, IEEE80211_C_BITS);
	putchar('\n');
}

static void
list_wme(const char *ifname)
{
#define	GETPARAM() \
	(get80211priv(ifname, IEEE80211_IOCTL_GETWMMPARAMS, param, sizeof(param)) != -1)
	static const char *acnames[] = { "AC_BE", "AC_BK", "AC_VI", "AC_VO" };
	int param[3];
	int ac;

	param[2] = 0;		/* channel params */
	for (ac = WME_AC_BE; ac <= WME_AC_VO; ac++) {
again:
		if (param[2] != 0)
			printf("\t%s", "     ");
		else
			printf("\t%s", acnames[ac]);

		param[1] = ac;

		/* show WME BSS parameters */
		param[0] = IEEE80211_WMMPARAMS_CWMIN;
		if (GETPARAM())
			printf(" cwmin %2u", param[0]);
		param[0] = IEEE80211_WMMPARAMS_CWMAX;
		if (GETPARAM())
			printf(" cwmax %2u", param[0]);
		param[0] = IEEE80211_WMMPARAMS_AIFS;
		if (GETPARAM())
			printf(" aifs %2u", param[0]);
		param[0] = IEEE80211_WMMPARAMS_TXOPLIMIT;
		if (GETPARAM())
			printf(" txopLimit %3u", param[0]);
		param[0] = IEEE80211_WMMPARAMS_ACM;
		if (GETPARAM()) {
			if (param[0])
				printf(" acm");
			else if (verbose)
				printf(" -acm");
		}
		/* !BSS only */
		if (param[2] == 0) {
			param[0] = IEEE80211_WMMPARAMS_NOACKPOLICY;
			if (GETPARAM()) {
				if (param[0])
					printf(" -ack");
				else if (verbose)
					printf(" ack");
			}
		}
		printf("\n");
		if (param[2] == 0) {
			param[2] = 1;		/* bss params */
			goto again;
		} else
			param[2] = 0;
	}
}

int
char2addr(char* addr)
{
    int i, j=2;

    for(i=2; i<17; i+=3) {
        addr[j++] = addr[i+1];
        addr[j++] = addr[i+2];
    }

    for(i=0; i<12; i++) {
        /* check 0~9, A~F */
        addr[i] = ((addr[i]-48) < 10) ? (addr[i] - 48) : (addr[i] - 55);
        /* check a~f */
        if ( addr[i] >= 42 )
            addr[i] -= 32;
        if ( addr[i] > 0xf )
            return -1;
    }

    for(i=0; i<6; i++)
        addr[i] = (addr[(i<<1)] << 4) + addr[(i<<1)+1];

    return 0;
}

#if UMAC_SUPPORT_NAWDS
static int handle_nawds(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
			char *addr, int value)
{
    int i;
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;
    char macaddr[MACSTR_LEN];

    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_NAWDS_SET_ADDR ||
        cmdtype == IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR) {
        if (strlen(addr) != 17) {
            printf("Invalid MAC address (format: xx:xx:xx:xx:xx:xx)\n");
            return -1;
        }
        memset(macaddr, '\0', sizeof(macaddr));
        strlcpy(macaddr, addr, sizeof(macaddr));

        if (char2addr(macaddr) != 0) {
            printf("Invalid MAC address\n");
            return -1;
        }
    }
    /* fill up configuration */
    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = cmdtype;
    switch (cmdtype) {
        case IEEE80211_WLANCONFIG_NAWDS_SET_MODE:
            config.data.nawds.mode = value;
            break;
        case IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS:
            config.data.nawds.defcaps = value;
            break;
        case IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE:
            config.data.nawds.override = value;
            break;
        case IEEE80211_WLANCONFIG_NAWDS_SET_ADDR:
            memcpy(config.data.nawds.mac, macaddr, IEEE80211_ADDR_LEN);
            config.data.nawds.caps = value;
            break;
        case IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR:
            memcpy(config.data.nawds.mac, macaddr, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_WLANCONFIG_NAWDS_GET:
            config.data.nawds.num = 0;
            break;
    }

    /* fill up request */
    iwr.u.data.pointer = (void*) &config;
    iwr.u.data.length = sizeof(struct ieee80211_wlanconfig);

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed");
        return -1;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_NAWDS_GET) {
        /* output the current configuration */
        printf("NAWDS configuration: \n");
        printf("Num     : %d\n", config.data.nawds.num);
        printf("Mode    : %d\n", config.data.nawds.mode);
        printf("Defcaps : %d\n", config.data.nawds.defcaps);
        printf("Override: %d\n", config.data.nawds.override);
        for (i = 0; i < config.data.nawds.num; i++) {
            config.data.nawds.num = i;
            if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
                perror("config_generic failed");
                return -1;
            }
            printf("%d: %02x:%02x:%02x:%02x:%02x:%02x %x\n",
                i,
                config.data.nawds.mac[0], config.data.nawds.mac[1],
                config.data.nawds.mac[2], config.data.nawds.mac[3],
                config.data.nawds.mac[4], config.data.nawds.mac[5],
                config.data.nawds.caps);
        }
    }

    return 0;
}
#endif

#if UMAC_SUPPORT_WNM

#define FMS_REQUEST_STR "fms_request {"
#define FMS_ELEMENT_STR "fms_subelement {"
#define TFS_REQUEST_STR "tfs_request {"
#define TCLAS_ELEMENT_STR "tclaselement {"
#define SUBELEMENT_STR "subelement {"
#define ACTION_STR "action_code {"
static char * config_get_line(char *s, int size, FILE *stream, char **_pos)
{
    char *pos, *end, *sstart;

    while (fgets(s, size, stream)) {
        s[size - 1] = '\0';
        pos = s;

        /* Skip white space from the beginning of line. */
       while (*pos == ' ' || *pos == '\t' || *pos == '\r')
            pos++;

        /* Skip comment lines and empty lines */
        if (*pos == '#' || *pos == '\n' || *pos == '\0')
            continue;

        /*
         * Remove # comments unless they are within a double quoted
         * string.
         */
        sstart = strchr(pos, '"');
        if (sstart)
            sstart = strrchr(sstart + 1, '"');
        if (!sstart)
            sstart = pos;
        end = strchr(sstart, '#');
        if (end)
            *end-- = '\0';
        else
            end = pos + strlen(pos) - 1;

        /* Remove trailing white space. */
        while (end > pos &&
               (*end == '\n' || *end == ' ' || *end == '\t' ||
            *end == '\r'))
            *end-- = '\0';
        if (*pos == '\0')
            continue;

        if (_pos)
            *_pos = pos;
        return pos;
    }
    if (_pos)
        *_pos = NULL;
    return NULL;
}

int
config_get_param_value(char *buf, char *pos, char *param, char *value)
{
    char *pos2, *pos3;

    pos2 = strchr(pos, '=');
    if (pos2 == NULL) {
        return -1;
    }
    pos3 = pos2 - 1;
    while (*pos3 && ((*pos3 == ' ') || (*pos3 == '\t'))) {
        pos3--;
    }
    if (*pos3) {
        pos3[1] = 0;
    }
    pos2 ++;
    while ((*pos2 == ' ') || (*pos2 == '\t')) {
        pos2++;
    }
    if (*pos2 == '"') {
        if (strchr(pos2 + 1, '"') == NULL) {
            return -1;
        }
    }
    strcpy(param, pos);
    strcpy(value, pos2);
    return 0;
}

int parse_tclas_element(FILE *fp, struct tfsreq_tclas_element *tclas)
{
    char buf[256] = {0};
    char *pos = NULL;
    char *pos2 = NULL;
    char *pos3 = NULL;
    char param[50] = {0};
    char value[50] = {0};
    int end=0;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;

    while(config_get_line(buf, sizeof(buf), fp, &pos)) {
        if (strcmp(pos, "}") == 0) {
            end = 1;
            break;
        }
        config_get_param_value(buf, pos, param, value);
        if (strcmp(param, "classifier_type") == 0) {
            tclas->classifier_type = atoi(value);
        }
        if (strcmp(param, "classifier_mask") == 0) {
            tclas->classifier_mask = atoi(value);
        }
        if (strcmp(param, "priority") == 0) {
            tclas->priority = atoi(value);
        }
        if (strcmp(param, "filter_offset") == 0) {
            tclas->clas.clas3.filter_offset = atoi(value);
        }
        if (strcmp(param, "filter_value") == 0) {
            int i;
            int len;
            u_int8_t lbyte = 0, ubyte = 0;

            len = strlen(value);
            for (i = 0; i < len; i += 2) {
                if ((value[i] >= '0') && (value[i] <= '9'))  {
                    ubyte = value[i] - '0';
                } else if ((value[i] >= 'A') && (value[i] <= 'F')) {
                    ubyte = value[i] - 'A' + 10;
                } else if ((value[i] >= 'a') && (value[i] <= 'f')) {
                    ubyte = value[i] - 'a' + 10;
                }
                if ((value[i + 1] >= '0') && (value[i + 1] <= '9'))  {
                    lbyte = value[i + 1] - '0';
                } else if ((value[i + 1] >= 'A') && (value[i + 1] <= 'F')) {
                    lbyte = value[i + 1] - 'A' + 10;
                } else if ((value[i + 1] >= 'a') && (value[i + 1] <= 'f')) {
                    lbyte = value[i + 1] - 'a' + 10;
                }
                tclas->clas.clas3.filter_value[i / 2] = (ubyte << 4) | lbyte;
            }
            tclas->clas.clas3.filter_len = len / 2;
        }
        if (strcmp(param, "filter_mask") == 0) {
            int i;
            int len;
            u_int8_t lbyte = 0, ubyte = 0;

            len = strlen(value);
            for (i = 0; i < len; i += 2) {
                if ((value[i] >= '0') && (value[i] <= '9'))  {
                    ubyte = value[i] - '0';
                } else if ((value[i] >= 'A') && (value[i] <= 'F')) {
                    ubyte = value[i] - 'A' + 10;
                } else if ((value[i] >= 'a') && (value[i] <= 'f')) {
                    ubyte = value[i] - 'a' + 10;
                }
                if ((value[i + 1] >= '0') && (value[i + 1] <= '9'))  {
                    lbyte = value[i + 1] - '0';
                } else if ((value[i + 1] >= 'A') && (value[i + 1] <= 'F')) {
                    lbyte = value[i + 1] - 'A' + 10;
                } else if ((value[i + 1] >= 'a') && (value[i + 1] <= 'f')) {
                    lbyte = value[i + 1] - 'a' + 10;
                }
                tclas->clas.clas3.filter_mask[i / 2] = (ubyte << 4) | lbyte;
            }
            tclas->clas.clas3.filter_len = len / 2;
        }
        if (strcmp(param, "version") == 0) {
            tclas->clas.clas14.clas14_v4.version = atoi(value);
        }
        if (strcmp(param, "sourceport") == 0) {
            tclas->clas.clas14.clas14_v4.source_port = atoi(value);
        }
        if (strcmp(param, "destport") == 0) {
            tclas->clas.clas14.clas14_v4.dest_port = atoi(value);
        }
        if (strcmp(param, "dscp") == 0) {
            tclas->clas.clas14.clas14_v4.dscp = atoi(value);
        }
        if (strcmp(param, "protocol") == 0) {
            tclas->clas.clas14.clas14_v4.protocol = atoi(value);
        }
        if (strcmp(param, "flowlabel") == 0) {
            int32_t flow;
            flow = atoi(value);
            memcpy(&tclas->clas.clas14.clas14_v6.flow_label, &flow, 3);
        }
        if (strcmp(param, "nextheader") == 0) {
            tclas->clas.clas14.clas14_v6.clas4_next_header = atoi(value);
        }
        if (strcmp(param, "sourceip") == 0) {
            if(inet_pton(AF_INET, value, &ipv4.sin_addr) <= 0) {
                if(inet_pton(AF_INET6, value, &ipv6.sin6_addr) <= 0) {
                    break;
                } else {
                    tclas->clas.clas14.clas14_v6.version = 6;
                    memcpy(tclas->clas.clas14.clas14_v6.source_ip,
                                                &ipv6.sin6_addr, 16);
                }
            } else {
                tclas->clas.clas14.clas14_v4.version = 4;
                memcpy(tclas->clas.clas14.clas14_v4.source_ip,
                                        &ipv4.sin_addr, 4);
            }
        }
        if (strcmp(param, "destip") == 0) {
            if(inet_pton(AF_INET, value, &ipv4.sin_addr) <= 0) {
                if (inet_pton(AF_INET6, value, &ipv6.sin6_addr) <= 0) {
                    break;
                } else {
                    memcpy(tclas->clas.clas14.clas14_v6.dest_ip,
                            &ipv6.sin6_addr, 16);
                }
            } else {
                    memcpy(tclas->clas.clas14.clas14_v4.dest_ip,
                            &ipv4.sin_addr, 4);
            }
        }
    }
    if (!end) {
        printf("Error in Tclas Element \n");
        return -1;
    }

    return 0;
}

int parse_actioncode(FILE *fp, u_int8_t *tfs_actioncode)
{
#define DELETEBIT 0
#define NOTIFYBIT 1
    char param[50] = {0};
    char value[50] = {0};
    char buf[50] = {0};
    int end = 0;
    u_int8_t delete = 0, notify = 0;
    char *pos;

    while(config_get_line(buf, sizeof(buf), fp, &pos)) {
        if (strcmp(pos, "}") == 0) {
            end = 1;
            break;
        }
        config_get_param_value(buf, pos, param, value);
        if(strcmp(param, "delete") == 0) {
            delete = atoi(value);
        }
        if(strcmp(param, "notify") == 0) {
            notify = atoi(value);
        }
    }
    if (!end) {
        printf("Subelement Configuration is not correct\n");
        return -1;
    }
    if (delete == 1)
        *tfs_actioncode |= 1 << DELETEBIT;
    else
        *tfs_actioncode &= ~(1 << DELETEBIT);

    if(notify == 1)
        *tfs_actioncode |= 1 << NOTIFYBIT;
    else
        *tfs_actioncode &= ~(1 << NOTIFYBIT);

    return 0;
}


int parse_subelement(FILE *fp, int req_type, void *sub)
{
    int tclas_count = 0;
    int end = 0;
    int rate = 0;
    char *pos = NULL;
    char param[50] = {0};
    char value[50] = {0};
    char buf[50] = {0};
    void *subelem = NULL;
    struct tfsreq_subelement *tfs_subelem = (struct tfsreq_subelement *)sub;
    struct fmsreq_subelement *fms_subelem = (struct fmsreq_subelement *)sub;

    while (config_get_line(buf, sizeof(buf), fp, &pos)) {
        if (strcmp(pos, "}") == 0) {
            end = 1;
            break;
        }

        if (IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY == req_type) {
            config_get_param_value(buf, pos, param, value);
            if (strcmp(param, "delivery_interval") == 0) {
                fms_subelem->del_itvl = atoi(value);
            }

            config_get_param_value(buf, pos, param, value);
            if (strcmp(param, "maximum_delivery_interval") == 0) {
                fms_subelem->max_del_itvl = atoi(value);
            }

            config_get_param_value(buf, pos, param, value);
            if (strcmp(param, "multicast_rate") == 0) {
                rate = atoi(value);
                fms_subelem->rate_id.mask = rate & 0xff;
                fms_subelem->rate_id.mcs_idx = (rate >> 8) & 0xff;
                fms_subelem->rate_id.rate = (rate >> 16) & 0xffff;
            }
            if (strcmp(TCLAS_ELEMENT_STR, pos) == 0) {
                parse_tclas_element(fp, &fms_subelem->tclas[tclas_count++]);
            }

            config_get_param_value(buf, pos, param, value);
            if (strcmp(param, "tclas_processing") == 0) {
                fms_subelem->tclas_processing = atoi(value);
            }
        } else {

            if (strcmp(TCLAS_ELEMENT_STR, pos) == 0) {
                parse_tclas_element(fp, &tfs_subelem->tclas[tclas_count++]);
            }

            config_get_param_value(buf, pos, param, value);
            if (strcmp(param, "tclas_processing") == 0) {
                tfs_subelem->tclas_processing = atoi(value);
            }
        }

    }
    if (!end) {
        printf("Subelement Configuration is not correct\n");
        return -1;
    }
    if (IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY == req_type) {
        fms_subelem->num_tclas_elements = tclas_count;
    } else {
        tfs_subelem->num_tclas_elements = tclas_count;
    }

    return 0;
}

int parse_fmsrequest(FILE *fp, struct ieee80211_wlanconfig_wnm_fms_req *fms)
{
    char param[50] = {0};
    char value[50] = {0};
    int end = 0;
    char *pos = NULL;
    char buf[512] = {0};
    int subelement_count = 0;
    int status;

    while(config_get_line(buf, sizeof(buf), fp, &pos)) {
        if (strcmp(pos, "}") == 0) {
            end = 1;
            break;
        }
        config_get_param_value(buf, pos, param, value);
        if(strcmp(param, "fms_token") == 0) {
            fms->fms_token = atoi(value);
        }

        if (strcmp(FMS_ELEMENT_STR, pos) == 0) {
            status = parse_subelement(fp, IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY,
                                      (void *)&fms->subelement[subelement_count++]);
            if (status < 0) {
                break;
            }
        }
        fms->num_subelements = subelement_count;
    }

    if (!end) {
        printf("Subelement Configuration is not correct\n");
        return -1;
    }
    return 0;
}

int parse_tfsrequest(FILE *fp, struct ieee80211_wlanconfig_wnm_tfs_req *tfs)
{
    char param[50] = {0};
    char value[50] = {0};
    int end = 0;
    char *pos = NULL;
    char buf[512] = {0};
    int subelement_count = 0;
    int status;

    while (config_get_line(buf, sizeof(buf), fp, &pos)) {
        if (strcmp(pos, "}") == 0) {
            end = 1;
            break;
        }
        config_get_param_value(buf, pos, param, value);
        if (strcmp(param, "tfsid") == 0) {
            tfs->tfsid = atoi(value);
        }
        if (strcmp(ACTION_STR, pos) == 0) {
            status = parse_actioncode(fp, &tfs->actioncode);
            if (status < 0) {
                break;
            }
        }
        if (strcmp(SUBELEMENT_STR, pos) == 0) {
            status = parse_subelement(fp, IEEE80211_WLANCONFIG_WNM_TFS_ADD,
                                      (void *)&tfs->subelement[subelement_count++]);
            if (status < 0) {
                break;
            }
        }
        tfs->num_subelements = subelement_count;
    }

    if (!end) {
        printf("Subelement Configuration is not correct\n");
        return -1;
    }
    return 0;
}

static int handle_wnm(const char *ifname, int cmdtype, const char *arg1, const char *arg2)
{
    FILE *fp = NULL;
    char buf[512] = {0};
    char *pos = NULL;
    char *pos2 = NULL;
    char *pos3 = NULL;
    int end = 0;
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;
    struct ieee80211_wlanconfig_wnm_bssmax *bssmax;
    struct ieee80211_wlanconfig_wnm_tfs *tfs;
    struct ieee80211_wlanconfig_wnm_fms *fms;
    struct ieee80211_wlanconfig_wnm_tim *tim;
    struct ieee80211_wlanconfig_wnm_bssterm *bssterm;
    int subelement_count = 0;
    int req_count = 0;
    int status = 0;

    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }
    memset(&config, 0, sizeof(config));

    config.cmdtype = cmdtype;
    switch(cmdtype) {
        case IEEE80211_WLANCONFIG_WNM_SET_BSSMAX:
            if (atoi(arg1) <= 0 || atoi(arg1) > 65534) {
                perror(" Value must be within 1 to 65534 \n");
                return -1;
            }
            bssmax = &config.data.wnm.data.bssmax;
            bssmax->idleperiod = atoi(arg1);
            if (arg2) {
                bssmax->idleoption = atoi(arg2);
            }
            break;
        case IEEE80211_WLANCONFIG_WNM_GET_BSSMAX:
            break;
        case IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY:
        case IEEE80211_WLANCONFIG_WNM_TFS_ADD: {
            fp = fopen(arg1, "r");
            if (fp == NULL) {
                perror("Unabled to open config file");
                return -1;
            }
            while(config_get_line(buf, sizeof(buf), fp, &pos)) {
                if (strcmp(pos, "}") == 0) {
                    end = 1;
                    break;
                }
                if (cmdtype == IEEE80211_WLANCONFIG_WNM_TFS_ADD) {

                    tfs = &config.data.wnm.data.tfs;
                    if (strcmp(TFS_REQUEST_STR, pos) == 0) {

                        status = parse_tfsrequest(fp,
                                &tfs->tfs_req[req_count++]);

                        if (status < 0) {
                            break;
                        }
                    }
                    tfs->num_tfsreq = req_count;
                }
                else {
                    fms = &config.data.wnm.data.fms;

                    if (strcmp(FMS_REQUEST_STR, pos) == 0) {
                        status = parse_fmsrequest(fp,
                                &fms->fms_req[req_count++]);

                        if (status < 0) {
                            break;
                        }
                    }
                    fms->num_fmsreq = req_count;
                }
            }
            if (feof(fp)) {
                if (status == 0) {
                    end = 1;
                }
            }
            fclose(fp);
            if (!end) {
                printf("Bad Configuration file....\n");
                exit(0);
            }
            break;
        }
        case IEEE80211_WLANCONFIG_WNM_TFS_DELETE: {
            tfs = &config.data.wnm.data.tfs;
            tfs->num_tfsreq = 0;
            break;
        }
        case IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST: {
            u_int32_t timrate;

            tim = &config.data.wnm.data.tim;
            if (arg1) {
                tim->interval = atoi(arg1);
            }
            if (arg2) {
                timrate = atoi(arg2);
                tim->enable_highrate = timrate & IEEE80211_WNM_TIM_HIGHRATE_ENABLE;
                tim->enable_lowrate = timrate & IEEE80211_WNM_TIM_LOWRATE_ENABLE;
            }
        }
        case IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST:
            break;
        case IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION:
            bssterm = &config.data.wnm.data.bssterm;
            bssterm->delay = atoi(arg1);
            if (arg2)
                bssterm->duration = atoi(arg2);
            break;
        default:
            printf("Unknown option: %d\n", cmdtype);
            break;
    }

    iwr.u.data.pointer = (void*) &config;
    iwr.u.data.length = sizeof(struct ieee80211_wlanconfig);

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed beacuse of invalid values");
        return -1;
    }
    if (cmdtype == IEEE80211_WLANCONFIG_WNM_GET_BSSMAX) {
        printf("IdlePeriod    : %d\n", config.data.wnm.data.bssmax.idleperiod);
        printf("IdleOption    : %d\n", config.data.wnm.data.bssmax.idleoption);
    }
    if (cmdtype == IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST) {
        printf("TIM Interval     : %d\n", config.data.wnm.data.tim.interval);
        printf("High DataRateTim : %s\n",
              config.data.wnm.data.tim.enable_highrate ? "Enable" : "Disable");
        printf("Low DataRateTim : %s\n",
              config.data.wnm.data.tim.enable_lowrate ? "Enable" : "Disable");
    }
    return 0;
}
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static int handle_hmwds(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
			char *addr1, char *addr2)
{
    int i;
    struct iwreq iwr;
    struct ieee80211_wlanconfig *config;
    char wds_ni_macaddr[MACSTR_LEN] = {0}, wds_macaddr[MACSTR_LEN] = {0}, data[4096];

    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    if (addr1 && strlen(addr1) != 17) {
        printf("Invalid MAC address (format: xx:xx:xx:xx:xx:xx)\n");
        return -1;
    }

    if (addr2 && strlen(addr2) != 17) {
        printf("Invalid MAC address (format: xx:xx:xx:xx:xx:xx)\n");
        return -1;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR) {
        if (addr1) {
            memset(wds_macaddr, '\0', sizeof(wds_macaddr));
            strlcpy(wds_macaddr, addr1, sizeof(wds_macaddr));
            if (char2addr(wds_macaddr) != 0) {
                printf("Invalid MAC address1\n");
                return -1;
            }
        }

    } else {
        if (addr1) {
            memset(wds_ni_macaddr, '\0', sizeof(wds_ni_macaddr));
            strlcpy(wds_ni_macaddr, addr1, sizeof(wds_ni_macaddr));
            if (char2addr(wds_ni_macaddr) != 0) {
                printf("Invalid MAC address1\n");
                return -1;
            }
        }

        if (addr2) {
            memset(wds_macaddr, '\0', sizeof(wds_macaddr));
            strlcpy(wds_macaddr, addr2, sizeof(wds_macaddr));
            if (char2addr(wds_macaddr) != 0) {
                printf("Invalid MAC address2\n");
                return -1;
            }
        }
    }

    config = (struct ieee80211_wlanconfig *)data;
    memset(config, 0, sizeof *config);
    /* fill up configuration */
    config->cmdtype = cmdtype;
    switch (cmdtype) {
        case IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR:
            memcpy(config->data.hmwds.wds_ni_macaddr, wds_ni_macaddr, IEEE80211_ADDR_LEN);
            config->data.hmwds.wds_macaddr_cnt = 1;
            memcpy(config->data.hmwds.wds_macaddr, wds_macaddr, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR:
            memcpy(config->data.hmwds.wds_ni_macaddr, wds_ni_macaddr, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE:
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_ADDR:
            memcpy(config->data.hmwds.wds_ni_macaddr, wds_ni_macaddr, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_TABLE:
            break;
        case IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR:
            memcpy(config->data.hmwds.wds_macaddr, wds_macaddr, IEEE80211_ADDR_LEN);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_DUMP_WDS_ADDR:
            break;
    }

    /* fill up request */
    iwr.u.data.pointer = (void *) data;
    iwr.u.data.length = sizeof data;

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed");
        return -1;
    }

    switch (cmdtype) {
        case IEEE80211_WLANCONFIG_HMWDS_READ_ADDR:
            /* print MAC of host managed WDS node */
            printf("HOST MANAGED WDS nodes: \n");
            for (i = 0; i < config->data.hmwds.wds_macaddr_cnt; i++) {
                printf("\t%02x:%02x:%02x:%02x:%02x:%02x\n",
                        *(config->data.hmwds.wds_macaddr + i * IEEE80211_ADDR_LEN),
                        *(config->data.hmwds.wds_macaddr + i * IEEE80211_ADDR_LEN + 1),
                        *(config->data.hmwds.wds_macaddr + i * IEEE80211_ADDR_LEN + 2),
                        *(config->data.hmwds.wds_macaddr + i * IEEE80211_ADDR_LEN + 3),
                        *(config->data.hmwds.wds_macaddr + i * IEEE80211_ADDR_LEN + 4),
                        *(config->data.hmwds.wds_macaddr + i * IEEE80211_ADDR_LEN + 5));
            }
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_TABLE:
            printf("WDS nodes: \n");
            printf("DA\t\t\tNext Hop\t\tFlags: \n");
            struct ieee80211_wlanconfig_wds_table *wds_table = &config->data.wds_table;
            for (i = 0; i < wds_table->wds_entry_cnt; i++) {
                struct ieee80211_wlanconfig_wds *wds_entry =
                    &wds_table->wds_entries[i];
                printf("%02x:%02x:%02x:%02x:%02x:%02x\t",
                       wds_entry->destmac[0], wds_entry->destmac[1],
                       wds_entry->destmac[2], wds_entry->destmac[3],
                       wds_entry->destmac[4], wds_entry->destmac[5]);
                printf("%02x:%02x:%02x:%02x:%02x:%02x\t",
                       wds_entry->peermac[0], wds_entry->peermac[1],
                       wds_entry->peermac[2], wds_entry->peermac[3],
                       wds_entry->peermac[4], wds_entry->peermac[5]);
                printf("0x%x\n", wds_entry->flags);
            }
            break;
    }

    return 0;
}

static int handle_ald(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
			char *addr1, int enable)
{
    int i;
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;
    char ni_macaddr[MACSTR_LEN] = {0};

    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    if (addr1 && strlen(addr1) != 17) {
        printf("Invalid MAC address (format: xx:xx:xx:xx:xx:xx)\n");
        return -1;
    }

    if (addr1) {
        memset(ni_macaddr, '\0', sizeof(ni_macaddr));
        strlcpy(ni_macaddr, addr1, sizeof(ni_macaddr));
        if (char2addr(ni_macaddr) != 0) {
            printf("Invalid MAC address1\n");
            return -1;
        }
    }

    memset(&config, 0, sizeof config);
    /* fill up configuration */
    config.cmdtype = cmdtype;
    switch (cmdtype) {
        case IEEE80211_WLANCONFIG_ALD_STA_ENABLE:
            memcpy(config.data.ald.data.ald_sta.macaddr, ni_macaddr, IEEE80211_ADDR_LEN);
            config.data.ald.data.ald_sta.enable = (u_int32_t)enable;
            break;
    }

    /* fill up request */
    iwr.u.data.pointer = (void *) &config;
    iwr.u.data.length = sizeof config;

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed");
        return -1;
    }

    return 0;
}
#endif

#ifdef ATH_BUS_PM
static int suspend(const char *ifname, int suspend)
{
    struct ifreq ifr;
    int s, val = suspend;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        err(1, "socket(SOCK_DRAGM)");
    memset(&ifr, 0, sizeof(ifr));
    if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(s);
        return -1;
    }
    ifr.ifr_data = (void *) &val;
    if (ioctl(s, SIOCSATHSUSPEND, &ifr) < 0)
        err(1, "ioctl");
    close(s);
}
#endif

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
static int handle_hmmc(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype, char *ip_str, char *mask_str)
{
    int ip, mask;
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;

    if (cmdtype == IEEE80211_WLANCONFIG_HMMC_ADD ||
            cmdtype == IEEE80211_WLANCONFIG_HMMC_DEL) {
        if ((ip = inet_addr(ip_str)) == -1 || !ip) {
            printf("Invalid ip string %s\n", ip_str);
            return -1;
        }

        if (!(mask = inet_addr(mask_str))) {
            printf("Invalid ip mask string %s\n", mask_str);
            return -1;
        }
    }

    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    config.cmdtype = cmdtype;
    switch (cmdtype) {
        case IEEE80211_WLANCONFIG_HMMC_ADD:
        case IEEE80211_WLANCONFIG_HMMC_DEL:
            config.data.hmmc.ip = ip;
            config.data.hmmc.mask = mask;
            break;
        case IEEE80211_WLANCONFIG_HMMC_DUMP:
            break;
        default:
            perror("invalid cmdtype");
            return -1;
    }

    iwr.u.data.pointer = (void *) &config;
    iwr.u.data.length = sizeof(struct ieee80211_wlanconfig);

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed");
        return -1;
    }

    return 0;
}
#endif

static void
ieee80211_status(const char *ifname)
{
	/* XXX fill in */
}

static int
getsocket(void)
{
	static int s = -1;

	if (s < 0) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
			err(1, "socket(SOCK_DRAGM)");
	}
	return s;
}

static int
get80211param(const char *ifname, int param, void *data, size_t len)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
		fprintf(stderr, "ifname too long: %s\n", ifname);
		return -1;
	}
	iwr.u.mode = param;

	if (ioctl(getsocket(), IEEE80211_IOCTL_GETPARAM, &iwr) < 0) {
		perror("ioctl[IEEE80211_IOCTL_GETPARAM]");
		return -1;
	}
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(data, iwr.u.name, len);
	}
	return iwr.u.data.length;
}

static int
do80211priv(struct iwreq *iwr, const char *ifname, int op, void *data, size_t len)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))

	memset(iwr, 0, sizeof(iwr));
	strlcpy(iwr->ifr_name, ifname, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr->u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr->u.data.pointer = data;
		iwr->u.data.length = len;
	}

	if (ioctl(getsocket(), op, iwr) < 0) {
		static const char *opnames[] = {
			"ioctl[IEEE80211_IOCTL_SETPARAM]",
			"ioctl[IEEE80211_IOCTL_GETPARAM]",
			"ioctl[IEEE80211_IOCTL_SETKEY]",
			"ioctl[SIOCIWFIRSTPRIV+3]",
			"ioctl[IEEE80211_IOCTL_DELKEY]",
			"ioctl[SIOCIWFIRSTPRIV+5]",
			"ioctl[IEEE80211_IOCTL_SETMLME]",
			"ioctl[SIOCIWFIRSTPRIV+7]",
			"ioctl[IEEE80211_IOCTL_SETOPTIE]",
			"ioctl[IEEE80211_IOCTL_GETOPTIE]",
			"ioctl[IEEE80211_IOCTL_ADDMAC]",
			"ioctl[SIOCIWFIRSTPRIV+11]",
			"ioctl[IEEE80211_IOCTL_DELMAC]",
			"ioctl[SIOCIWFIRSTPRIV+13]",
			"ioctl[IEEE80211_IOCTL_CHANLIST]",
			"ioctl[SIOCIWFIRSTPRIV+15]",
			"ioctl[IEEE80211_IOCTL_GETRSN]",
			"ioctl[SIOCIWFIRSTPRIV+17]",
			"ioctl[IEEE80211_IOCTL_GETKEY]",
		};
		op -= SIOCIWFIRSTPRIV;
		if (0 <= op && op < N(opnames))
			perror(opnames[op]);
		else
			perror("ioctl[unknown???]");
		return -1;
	}
	return 0;
#undef N
}

static int
set80211priv(const char *ifname, int op, void *data, size_t len)
{
	struct iwreq iwr;

	return do80211priv(&iwr, ifname, op, data, len);
}

static int
get80211priv(const char *ifname, int op, void *data, size_t len)
{
	struct iwreq iwr;

	if (do80211priv(&iwr, ifname, op, data, len) < 0)
		return -1;
	if (len < IFNAMSIZ)
		memcpy(data, iwr.u.name, len);
	return iwr.u.data.length;
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}

#define MAX_NUM_SET_NOA     2   /* Number of set of NOA schedule to set */
static int set_p2p_noa(const char *ifname, char ** curargs)
{
	char ** curptr = curargs;
	struct ieee80211_p2p_go_noa go_noa[MAX_NUM_SET_NOA];
    int num_noa_set = 0;
    int i;
    struct iwreq iwr;


    while (num_noa_set < MAX_NUM_SET_NOA) {
        if (*curptr) {
            int input_param = atoi(*curptr);

            if (input_param > 255) {
                printf("Invalid Number of iterations. Equal 1 for one-shot.\n\tPeriodic is 2-254. 255 is continuous. 0 is removed\n");
                goto setcmd_p2pnoa_err;
            }

            go_noa[num_noa_set].num_iterations = (u_int8_t)input_param;

        } else{
            goto setcmd_p2pnoa_err;
        }
        curptr++;

        if (*curptr) {
            go_noa[num_noa_set].offset_next_tbtt = (u_int16_t)atoi(*curptr);
        } else{
            goto setcmd_p2pnoa_err;
        }
        curptr++;

        if (*curptr) {
            go_noa[num_noa_set].duration = (u_int16_t)atoi(*curptr);
        } else{
            goto setcmd_p2pnoa_err;
        }

        if ((go_noa[num_noa_set].num_iterations == 0) && (go_noa[num_noa_set].duration != 0)) {
            printf("Error: Invalid Number of iterations. To remove NOA, the duration must also be 0.\n");
            goto setcmd_p2pnoa_err;
        }

        num_noa_set++;

        /* Check if there is another set */
        curptr++;

        if (*curptr == NULL) {
            /* we are done*/
            break;
        }
    }


    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        goto setcmd_p2pnoa_err;
    }

    iwr.u.data.pointer = (void *) &(go_noa[0]);
    iwr.u.data.length = sizeof(struct ieee80211_p2p_go_noa) * num_noa_set;
    iwr.u.data.flags = IEEE80211_IOC_P2P_GO_NOA;

	if (ioctl(getsocket(), IEEE80211_IOCTL_P2P_BIG_PARAM, &iwr) < 0)
		err(1, "ioctl: failed to set p2pgo_noa\n");

	printf("%s  p2pgo_noa for", iwr.ifr_name);
    for (i = 0; i < num_noa_set; i++) {
        printf(", [%d] %d %d %d", i, go_noa[i].num_iterations,
                         go_noa[i].offset_next_tbtt, go_noa[i].duration);
        if (go_noa[i].num_iterations == 1) {
            printf(" (one-shot NOA)");
        }
        if (go_noa[i].num_iterations == 255) {
            printf(" (continuous NOA)");
        }
        else {
            printf(" (%d iterations NOA)", (unsigned int)go_noa[i].num_iterations);
        }
    }
    printf("\n");

	return 1;

setcmd_p2pnoa_err:
	printf("Usage: wlanconfig wlanX p2pgonoa <num_iteration:1-255> <offset from tbtt in msec> < duration in msec> {2nd set} \n");
	return 0;
}

#define _ATH_LINUX_OSDEP_H
#define _WBUF_H
#define _IEEE80211_API_H_
typedef int ieee80211_scan_params;
typedef int wlan_action_frame_complete_handler;
typedef int wbuf_t;
typedef int bool;
#include "include/ieee80211P2P_api.h"
static int get_noainfo(const char *ifname)
{
	/*
	 * Handle the ssid get cmd
	 */
    struct iwreq iwr;
    wlan_p2p_noa_info noa_info;
    int i;

    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    iwr.u.data.pointer = (void *) &(noa_info);
    iwr.u.data.length = sizeof(noa_info);
    iwr.u.data.flags = IEEE80211_IOC_P2P_NOA_INFO;

	if (ioctl(getsocket(), IEEE80211_IOCTL_P2P_BIG_PARAM, &iwr) < 0)
		err(1, "ioctl: failed to get noa info\n");
	printf("%s  noainfo : \n", iwr.ifr_name);
	printf("tsf %d index %d oppPS %d ctwindow %d  \n",
           noa_info.cur_tsf32, noa_info.index, noa_info.oppPS, noa_info.ctwindow );
	printf("num NOA descriptors %d  \n",noa_info.num_descriptors);
    for (i=0;i<noa_info.num_descriptors;++i) {
        printf("descriptor %d : type_count %d duration %d interval %d start_time %d  \n",i,
           noa_info.noa_descriptors[i].type_count,
           noa_info.noa_descriptors[i].duration,
           noa_info.noa_descriptors[i].interval,
           noa_info.noa_descriptors[i].start_time );
    }
	return 1;
}

static int set_max_rate(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype,
                        char *addr, u_int8_t maxrate)
{
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;
    char macaddr[MACSTR_LEN] = {0};

    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_SET_MAX_RATE) {
        if (strlen(addr) != (MACSTR_LEN - 1)) {
            printf("Invalid MAC address (format: xx:xx:xx:xx:xx:xx)\n");
            return -1;
        }
        memset(macaddr, '\0', sizeof(macaddr));
        strlcpy(macaddr, addr, sizeof(macaddr));

        if (char2addr(macaddr) != 0) {
            printf("Invalid MAC address\n");
            return -1;
        }
    }

    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = cmdtype;
    memcpy(config.smr.mac, macaddr, IEEE80211_ADDR_LEN);
    config.smr.maxrate = maxrate;
    iwr.u.data.pointer = (void*) &config;
    iwr.u.data.length = sizeof(struct ieee80211_wlanconfig);

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed");
        return -1;
    }

    return 0;
}

#if ATH_SUPPORT_WRAP
static int handle_macaddr(char *mac_str, u_int8_t *mac_addr)
{
    char tmp[MACSTR_LEN];

    if (strlen(mac_str) != 17) {
        printf("Invalid wlanaddr MAC address '%s', should be in format: "
                "(xx:xx:xx:xx:xx:xx)\n", mac_str);
        return -1;
    }
    memset(tmp, '\0', sizeof(tmp));
    strlcpy(tmp, mac_str, sizeof(tmp));

    if (char2addr(tmp) != 0) {
        printf("Invalid MAC address: %s\n", tmp);
        return -1;
    }

    memcpy(mac_addr, tmp, IEEE80211_ADDR_LEN);
    return 0;
}
#endif


#if ATH_SUPPORT_DYNAMIC_VENDOR_IE

/* convert chararray to hex */
int
char2hex(char *charstr)
{
    int i ;
    int hex_len, len = strlen(charstr);

    for(i=0; i<len; i++) {
        /* check 0~9, A~F */
        charstr[i] = ((charstr[i]-48) < 10) ? (charstr[i] - 48) : (charstr[i] - 55);
        /* check a~f */
        if ( charstr[i] >= 42 )
            charstr[i] -= 32;
        if ( charstr[i] > 0xf )
            return -1;
    }

    /* hex len is half the string len */
    hex_len = len /2 ;
    if (hex_len *2 < len)
	hex_len ++;

    for(i=0; i<hex_len; i++)
        charstr[i] = (charstr[(i<<1)] << 4) + charstr[(i<<1)+1];

    return 0;
}

static int handle_vendorie(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype, int len, char *in_oui, char *in_cap_info, char *in_ftype_map)
{
    struct iwreq iwr;
    u_int8_t ie_buf[MAX_VENDOR_BUF_LEN + 12];
    struct ieee80211_wlanconfig_vendorie *vie = (struct ieee80211_wlanconfig_vendorie *) &ie_buf;
    /* From input every char occupies 1 byte and  +1 to include the null string in end */
    char oui[VENDORIE_OUI_LEN *2 + 1], *cap_info = NULL, ftype_map[3];
    int i, j = 0, k;
    u_int8_t *ie_buffer;
    u_int32_t ie_len;
    int block_length = 0;
    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    /* Param length check & conversion */

    if (cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_ADD || cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE) {

        if (len >= MAX_VENDOR_IE_LEN || (len *2 != (strlen(in_oui) + strlen(in_cap_info))) || (len < 0)) {
            printf(" Len does not Match , either Invalid/exceeded max/min Vendor IE len \n");
            return -1;
        }

        if (strlen(in_oui) != VENDORIE_OUI_LEN*2) {
            printf("Invalid OUI , OUI expected always 3 byte, format: xxxxxx)\n");
            return -1;
        }

        strlcpy(oui, in_oui, (VENDORIE_OUI_LEN * 2) + 1);


        if (char2hex(oui) != 0) {
            printf("Invalid OUI Hex String , Corret Len & OUI field \n");
            return -1;
        }

        if (strlen(in_cap_info) != (len - VENDORIE_OUI_LEN) *2) {
            printf("Invalid len , capability len =%d  not matching with total len=%d (bytes) , format: xxxxxxxx)\n", strlen(in_cap_info),len);
            return -1;
        }

        cap_info = malloc((len - VENDORIE_OUI_LEN) *2 + 1);

        if(!cap_info) {
            fprintf (stderr, "Unable to allocate memory for Vendor IE Cap_info \n");
            return -1;
        }
        strlcpy(cap_info, in_cap_info, (((len - VENDORIE_OUI_LEN) * 2) + 1));

        if (char2hex(cap_info) != 0) {
            printf("Invalid capability Hex String , Corret Len & Cap_Info field \n");
            return -1;
        }

        if (strlen(in_ftype_map) != 2) {
            printf("Invalid frame maping , expected always 2 byte, format: xxxx)\n");
            return -1;
        }

        strlcpy(ftype_map, in_ftype_map, (2 + 1));

        if (char2hex(ftype_map) != 0) {
            printf("Invalid frame maping Hex String \n");
            return -1;
        }
    }

    if (cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_LIST || cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE) {
        if (len != 4 && len != 3 && len != 0){
            printf(" Invalid length ...Expected length is 3 or 0 for list command and 4 for remove command\n");
            return -1;
        }
        if(len != 0)
        {
            if (strlen(in_oui) != VENDORIE_OUI_LEN*2) {
                printf("Invalid OUI , OUI expected always 3 byte, format: xxxxxx)\n");
                return -1;
            }
            strlcpy(oui, in_oui, ((VENDORIE_OUI_LEN * 2) + 1));
            if (char2hex(oui) != 0) {
                printf("Invalid OUI Hex String , Corret Len & OUI field \n");
                return -1;
            }
        }
    }

    if(cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE)
    {
        if (len != 4) {
            printf(" Invalid length ...Expected length is 4\n");
            return -1;
        }
        if (strlen(in_cap_info) != (len - VENDORIE_OUI_LEN) *2) {
            printf("Invalid len , capability len =%d  not matching with total len=%d (bytes) , format: xxxxxxxx)\n", strlen(in_cap_info),len);
            return -1;
        }

        cap_info = malloc((len - VENDORIE_OUI_LEN) *2 + 1);

        if(!cap_info) {
            fprintf (stderr, "Unable to allocate memory for Vendor IE Cap_info \n");
            return -1;
        }
        strlcpy(cap_info, in_cap_info, (((len - VENDORIE_OUI_LEN) * 2) + 1));

        if (char2hex(cap_info) != 0) {
            printf("Invalid capability Hex String , Corret Len & Cap_Info field \n");
            return -1;
        }
    }

    /* fill up configuration */
    memset(ie_buf, 0, MAX_VENDOR_BUF_LEN + 12);
    vie->cmdtype = cmdtype;

    switch (cmdtype) {
        case IEEE80211_WLANCONFIG_VENDOR_IE_ADD:
        case IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE:
             vie->ie.id = IEEE80211_ELEMID_VENDOR; /*default vendor ie value */
             memcpy(vie->ie.oui, oui,VENDORIE_OUI_LEN);
             memcpy(vie->ie.cap_info, cap_info, (len - VENDORIE_OUI_LEN));
             memcpy(&vie->ftype_map, ftype_map, 1);
             vie->ie.len = len;
             vie->tot_len = len + 12;
            break;

        case IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE:
             vie->ie.id = IEEE80211_ELEMID_VENDOR;
             memcpy(vie->ie.oui, oui,VENDORIE_OUI_LEN);
             memcpy(vie->ie.cap_info, cap_info, (len - VENDORIE_OUI_LEN));
             vie->ie.len = len;
             vie->tot_len = len + 12;
            break;
        case IEEE80211_WLANCONFIG_VENDOR_IE_LIST:
             if(len == 0)
             {
                 vie->ie.id = 0x0;
                 vie->ie.len = 0;
                 vie->tot_len = MAX_VENDOR_BUF_LEN + 12;
                 break;
             }
             vie->ie.id = IEEE80211_ELEMID_VENDOR;
             memcpy(vie->ie.oui, oui,VENDORIE_OUI_LEN);
             vie->ie.len = len;
             vie->tot_len = MAX_VENDOR_BUF_LEN + 12;
            break;

    }
    /* fill up request */
    iwr.u.data.pointer = (void*) &ie_buf;
    iwr.u.data.length = vie->tot_len;

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic failed in handle_vendorie()");
        return -1;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE) {
        printf(" Vendor IE Successfully Removed \n");
    }

    /*output configuration*/
    if(cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_ADD || cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE)
    {
        printf("\n----------------------------------------\n");
        printf("Adding or updating following vendor ie\n");
        printf("Vendor IE info Ioctl CMD id     : %d \n",cmdtype);
        printf("ID                              : %2x\n", vie->ie.id);
        printf("Len (OUI+ Pcapdata) in Bytes    : %d\n", vie->ie.len);
        printf("OUI                             : %02x%02x%02x\n", vie->ie.oui[0],vie->ie.oui[1],vie->ie.oui[2]);
        printf("Private capibility_data         : ");
        for (i = 0; i < (vie->ie.len - VENDORIE_OUI_LEN); i++)
        {
            printf("%02x", vie->ie.cap_info[i]);
        }
        if (cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_ADD)
        {
            printf("\nFrame Include Mask              : %02x", vie->ftype_map);
        }
        printf("\n----------------------------------------\n");
    }
    if (cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE)
    {
        printf("\n----------------------------------------\n");
        printf("Removing following vendor IEs matching OUI type and subtype\n");
        printf("Vendor IE info Ioctl CMD id     : %d \n",cmdtype);
        printf("ID                              : %02x\n", vie->ie.id);
        printf("OUI                             : %02x%02x%02x\n", vie->ie.oui[0],vie->ie.oui[1],vie->ie.oui[2]);
        if(vie->ie.cap_info[0] == 0xff)
        {
            printf("Subtype                         : all subtypes");
        }
        else
        {
            printf("Subtype                         : %02x",vie->ie.cap_info[0]);
        }
        printf("\n----------------------------------------\n");
    }
    /*
     * The list command returns a buffer containing multiple IEs.
     * The frame format of the buffer is as follows:
     * |ftype|type|length|OUI|pcap_data|
     * The buffer is traversed and the individual IEs are printed separately
     */
    if (cmdtype == IEEE80211_WLANCONFIG_VENDOR_IE_LIST)
    {
        printf("\n----------------------------------------\n");
        printf("Listing vendor IEs matching the following OUI type\n");
        printf("Vendor IE info Ioctl CMD id     : %d \n",cmdtype);
        ie_buffer = (u_int8_t *) &vie->ie;
        ie_len = iwr.u.data.length - 12;
        printf("Total length = %d ",ie_len);
        if((ie_len <= 0) || (ie_len >= MAX_VENDOR_BUF_LEN))
        {
            goto exit;
        }
        j = 0;
	/* Buffer format:
	 * +-----------------------------------------------+
	   |F|T|L|  V of L bytes  |F|T|L| V of L bytes     |
           +-----------------------------------------------+
	*/
        while((j+2 < ie_len) && (j+ie_buffer[j+2]+2 < ie_len))
        {
            block_length = ie_buffer[j+2] + 3;
            printf("\n\nFrame type                      : %2x\n", ie_buffer[j]);
            printf("ID                              : %2x\n", ie_buffer[j+1]);
            printf("Length                          : %d\n", ie_buffer[j+2]);
            printf("OUI                             : %02x%02x%02x\n", ie_buffer[j+3],ie_buffer[j+4],ie_buffer[j+5]);
            printf("Private capibility_data         : ");
            for(k = j+6; k < (j+block_length); k++)
            {
                printf("%02x ", ie_buffer[k]);
            }
            j += block_length;
        }
        printf("\n----------------------------------------\n");
    }
exit:
    free(cap_info);
    return 0;
}
#endif

#if ATH_SUPPORT_NAC
static int handle_nac(const char *ifname, IEEE80211_WLANCONFIG_CMDTYPE cmdtype, int argc, char *argv[])
{
    int i, j, max_addrlimit = 0;
    struct iwreq iwr;
    struct ieee80211_wlanconfig config;
    char macaddr[MACSTR_LEN];
    char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


    memset(&iwr, 0, sizeof(struct iwreq));
    if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        return -1;
    }

    /* zero out configuration */
    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));

    if (streq(argv[4], "bssid")) {

        max_addrlimit = NAC_MAX_BSSID;
        config.data.nac.mac_type = IEEE80211_NAC_MACTYPE_BSSID;

    } else if (streq(argv[4], "client")) {

        max_addrlimit = NAC_MAX_CLIENT;
        config.data.nac.mac_type = IEEE80211_NAC_MACTYPE_CLIENT;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_NAC_ADDR_ADD ||
        cmdtype == IEEE80211_WLANCONFIG_NAC_ADDR_DEL) {

        for(i=0, j=5; i < max_addrlimit, j < argc ; i++, j++) {

            if (strlen(argv[j]) != 17) {
                printf("Invalid MAC address (format: xx:xx:xx:xx:xx:xx)\n");
                return -1;
            }

            memset(macaddr, '\0', sizeof(macaddr));
            strlcpy(macaddr, argv[j] , sizeof(macaddr));

            if (char2addr(macaddr) != 0) {
                printf( "Invalid MAC address\n");
                return -1;
            }

        memcpy(config.data.nac.mac_list[i], macaddr, IEEE80211_ADDR_LEN);

        }
    }

    /* fill up cmd */
    config.cmdtype = cmdtype;

    /* fill up request */
    iwr.u.data.pointer = (void*) &config;
    iwr.u.data.length = sizeof(struct ieee80211_wlanconfig);

    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        perror("config_generic Nac command failed");
        return -1;
    }

    if (cmdtype == IEEE80211_WLANCONFIG_NAC_ADDR_LIST) {
        /* output the current configuration */
        if(config.data.nac.mac_type == IEEE80211_NAC_MACTYPE_BSSID) {
            printf("NAC BSSID configuration: \n");

        } else {
            printf("NAC CLIENT configuration: \n");
        }

        for (i = 0; i < max_addrlimit; i++) {

            if (memcmp(config.data.nac.mac_list[i], nullmac, IEEE80211_ADDR_LEN) != 0) {
                printf("%d-  %02x:%02x:%02x:%02x:%02x:%02x ",
                    i+1,
                    config.data.nac.mac_list[i][0], config.data.nac.mac_list[i][1],
                    config.data.nac.mac_list[i][2], config.data.nac.mac_list[i][3],
                    config.data.nac.mac_list[i][4], config.data.nac.mac_list[i][5]);
                if (config.data.nac.mac_type == IEEE80211_NAC_MACTYPE_CLIENT) {
                    printf("rssi %d \n", config.data.nac.rssi[i]);
                } else {
                    printf("\n");
                }
            }
        }
    }
    return 0;
}
#endif
