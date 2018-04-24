/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  icm.c
 *
 *    Description:  Intelligent Channel Manager
 *
 *        Version:  1.0
 *        Created:  04/19/2012 01:17:17 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "icm.h"
#include "icm_api.h"
#include "ieee80211_external.h"
#include "ath_classifier.h"

#define EXPECTED_MAX_VAPS       (30 * MAX_DEV_NUM)
/* main data structure for icm */
ICM_INFO_T icm;
ICM_DEV_INFO_T  dev;
ICM_DEV_INFO_T* pdev = &dev;

/* String mappings for some enumerations.
 * Note: The short strings under *_shortstr[] below must NOT exceed
 * SHORTSTRWIDTH characters.
 */

/* String mappings for ICM_CHAN_RELATIONSHIP_T */
const char *icm_chan_relationship_str[] = {
    "Primary itself",                      /* ICM_CHAN_RELATIONSHIP_SELF      */
    "Outside bonding span but adjacent",   /* ICM_CHAN_RELATIONSHIP_ADJ       */
    "Overlapping channel",                 /* ICM_CHAN_RELATIONSHIP_OVLP      */
    "Secondary 20 MHz",                    /* ICM_CHAN_RELATIONSHIP_SEC20     */
    "In secondary 40 MHz",                 /* ICM_CHAN_RELATIONSHIP_SEC40     */
    "In secondary 80 MHz",                 /* ICM_CHAN_RELATIONSHIP_SEC80     */
    "Invalid enumeration",                 /* ICM_CHAN_RELATIONSHIP_INVALID   */
};

/* Short string mappings for ICM_CHAN_RELATIONSHIP_T */
const char *icm_chan_relationship_shortstr[] = {
    "Self",                                /* ICM_CHAN_RELATIONSHIP_SELF      */
    "Adj",                                 /* ICM_CHAN_RELATIONSHIP_ADJ       */
    "Ovlp",                                /* ICM_CHAN_RELATIONSHIP_OVLP      */
    "Sec20",                               /* ICM_CHAN_RELATIONSHIP_SEC20     */
    "Sec40",                               /* ICM_CHAN_RELATIONSHIP_SEC40     */
    "Sec80",                               /* ICM_CHAN_RELATIONSHIP_SEC80     */
    "Invld",                               /* ICM_CHAN_RELATIONSHIP_INVALID   */
};

/* String mappings for ICM_SELDBG_FSTATUS_T */
const char *icm_seldbg_fstatus_str[] = {
    "Not computed",                        /* ICM_SELDBG_FSTATUS_NOTCOMP      */
    "Not applicable",                      /* ICM_SELDBG_FSTATUS_NOTAPPL      */
    "Not required",                        /* ICM_SELDBG_FSTATUS_NOTREQ       */
    "Not used",                            /* ICM_SELDBG_FSTATUS_NOTUSED      */
    "Is set and valid",                    /* ICM_SELDBG_FSTATUS_SET          */
    "Invalid enumeration",                 /* ICM_SELDBG_FSTATUS_INVALID      */
};

/* Short string mappings for ICM_SELDBG_FSTATUS_T */
const char *icm_seldbg_fstatus_shortstr[] = {
    "NC",                                  /* ICM_SELDBG_FSTATUS_NOTCOMP      */
    "NA",                                  /* ICM_SELDBG_FSTATUS_NOTAPPL      */
    "NR",                                  /* ICM_SELDBG_FSTATUS_NOTREQ       */
    "NU",                                  /* ICM_SELDBG_FSTATUS_NOTUSED      */
    "Set",                                 /* ICM_SELDBG_FSTATUS_SET          */
    "Invld",                               /* ICM_SELDBG_FSTATUS_INVALID      */
};

/* String mappings for ICM_SELDBG_REJCODE_T*/
const char *icm_seldbg_rejcode_str[] = {
    "Not rejected",                        /* ICM_SELDBG_REJCODE_NOTREJ       */
    "Primary excluded by external entity", /* ICM_SELDBG_REJCODE_PRI_EXCLD    */
    "Bonding channel excluded by "
    "external entity",                     /* ICM_SELDBG_REJCODE_BOND_EXCLD   */
    "Overlapping channel excluded by "
    "external entity",                     /* ICM_SELDBG_REJCODE_OVLP_EXCLD   */
    "Primary channel incapable of PHY "
    "spec and/or width requested",         /* ICM_SELDBG_REJCODE_PRI_INCAP    */
    "Primary channel falls on secondary "
    "20 MHz of OBSS",                      /* ICM_SELDBG_REJCODE_PRI_SEC20    */
    "Primary channel falls on secondary "
    "40 MHz of 160/80+80 MHz OBSS",        /* ICM_SELDBG_REJCODE_PRI_SEC40    */
    "Bonding channel falls on primary "
    "20 MHz of OBSS",                      /* ICM_SELDBG_REJCODE_BOND_PRI20   */
    "Secondary 20 MHz already occupied "
    "by primary 20 MHz of OBSS",           /* ICM_SELDBG_REJCODE_SEC20_OCC    */
    "Secondary 40 MHz of desired "
    "160/80+80 MHz BSS already occupied "
    "by primary 20 MHz of OBSS",           /* ICM_SELDBG_REJCODE_SEC40_OCC    */
    "Overlapping channel falls on "
    "primary 20 MHz of OBSS",              /* ICM_SELDBG_REJCODE_OVLP_PRI20   */
    "Primary channel is a weather radar "
    "channel in the ETSI domain",          /* ICM_SELDBG_REJCODE_PRI_ETSIWTH  */
    "Bonding channel is a weather radar "
    "channel in the ETSI domain",          /* ICM_SELDBG_REJCODE_BOND_ETSIWTH */
    "Primary channel suffers CW "
    "interference",                        /* ICM_SELDBG_REJCODE_PRI_CW       */
    "Bonding channel suffers CW "
    "interference",                        /* ICM_SELDBG_REJCODE_BOND_CW      */
    "Invalid enumeration",                 /* ICM_SELDBG_REJCODE_INVALID      */
};

/* Short string mappings for ICM_SELDBG_REJCODE_T*/
const char *icm_seldbg_rejcode_shortstr[] = {
    "NotRej",                              /* ICM_SELDBG_REJCODE_NOTREJ       */
    "PriExcl",                             /* ICM_SELDBG_REJCODE_PRI_EXCLD    */
    "BndExcl",                             /* ICM_SELDBG_REJCODE_BOND_EXCLD   */
    "OvlExcl",                             /* ICM_SELDBG_REJCODE_OVLP_EXCLD   */
    "PriIncap",                            /* ICM_SELDBG_REJCODE_PRI_INCAP    */
    "PriOnSec20",                          /* ICM_SELDBG_REJCODE_PRI_SEC20    */
    "PriOnSec40",                          /* ICM_SELDBG_REJCODE_PRI_SEC40    */
    "BndOnPri20",                          /* ICM_SELDBG_REJCODE_BOND_PRI20   */
    "Sec20Taken",                          /* ICM_SELDBG_REJCODE_SEC20_OCC    */
    "Sec40Taken",                          /* ICM_SELDBG_REJCODE_SEC40_OCC    */
    "OvlOnPri20",                          /* ICM_SELDBG_REJCODE_OVLP_PRI20   */
    "PriETSI",                             /* ICM_SELDBG_REJCODE_PRI_ETSIWTH  */
    "BndETSI",                             /* ICM_SELDBG_REJCODE_BOND_ETSIWTH */
    "PriCW",                               /* ICM_SELDBG_REJCODE_PRI_CW       */
    "BndCW",                               /* ICM_SELDBG_REJCODE_BOND_CW      */
    "Inval Code",                          /* ICM_SELDBG_REJCODE_INVALID      */
};

/* String mappings for ICM_BAND_T */
const char *icm_band_str[] = {
    "2.4 GHz",                             /* ICM_BAND_2_4G                   */
    "5 GHz",                               /* ICM_BAND_5G                     */
    "Invalid enumeration",                 /* ICM_BAND_INVALID                */
};

/* String mappings for ICM_CH_BW_T */
const char *icm_ch_bw_str[] = {
    "20",                                  /* ICM_CH_BW_20                    */
    "40-",                                 /* ICM_CH_BW_40MINUS               */
    "40+",                                 /* ICM_CH_BW_40PLUS                */
    "40",                                  /* ICM_CH_BW_40                    */
    "80",                                  /* ICM_CH_BW_80                    */
    "160",                                 /* ICM_CH_BW_160                   */
    "80+80",                               /* ICM_CH_BW_80_PLUS_80            */
    "Invalid enumeration",                 /* ICM_CH_BW_INVALID               */
};

/* String mappings for ICM_PHY_SPEC_T*/
const char *icm_phy_spec_str[] = {
    "11A",                                 /* ICM_ PHY_SPEC_11A               */
    "11B",                                 /* ICM_ PHY_SPEC_11B               */
    "11G",                                 /* ICM_ PHY_SPEC_11G               */
    "FH",                                  /* ICM_ PHY_SPEC_FH                */
    "TURBO A",                             /* ICM_ PHY_SPEC_TURBO_A           */
    "TURBO G",                             /* ICM_ PHY_SPEC_TURBO_G           */
    "11NA",                                /* ICM_ PHY_SPEC_11NA              */
    "11NG",                                /* ICM_ PHY_SPEC_11NG              */
    "11AC",                                /* ICM_ PHY_SPEC_11AC              */
    "Invalid enumeration",                 /* ICM_ PHY_SPEC_INVALID           */
};

/* String mappings for booleans */
const char *icm_bool_str[] = {
    "False",                               /* False                           */
    "True",                                /* True                            */
};

/* Short string mappings for booleans */
const char *icm_bool_shortstr[] = {
    "F",                                   /* False                           */
    "T",                                   /* True                            */
};


/* Static function declarations */

static bool icm_is_vap_radiochild(const u_int8_t *vapaddr,
                                  const u_int8_t *radioaddr);

static int icm_sys_ifnames_init(sys_ifnames *ifs, int base_max_size);

static int icm_sys_ifnames_extend(sys_ifnames *ifs, int additional_size);

static void icm_sys_ifnames_deinit(sys_ifnames *ifs);

static int icm_sys_ifnames_add(sys_ifnames *ifs, char *ifname);

static int icm_build_vap_listing(sys_ifnames *vap_listing);

static int icm_is_dev_ap(ICM_DEV_INFO_T* pdev,
                         char *dev_ifname,
                         bool *isap);
static int icm_build_radio_listing(sys_ifnames *radio_listing);
static int icm_init_radio_iface(ICM_INFO_T* picm, char *radio_ifname);
static int icm_get_radio_default_channel(const char *ifname);
static int icm_get_radio_band(const char *ifname);
static int icm_get_radio_channel_width(const char *ifname);
static int icm_get_radio_phy_spec(const char *ifname);

/*
 * Function     : get_picm
 * Description  : get the pointer to icm info data structure
 * Input params : void
 * Return       : pointer to icm info structure
 *
 */
ICM_INFO_T* get_picm(int devid)
{
    if (devid < MAX_DEV_NUM) {
        return &pdev->icm[devid];
    } else {
        ICM_ASSERT(devid < MAX_DEV_NUM);
    }
    return NULL;
}

ICM_DEV_INFO_T* get_pdev(void)
{
    return pdev;
}

/*
 * Function     : cleanup
 * Description  : free acquried resources
 * Input params : pointer to ICM_INFO_T
 * Return       : void
 *
 */
void icm_cleanup(ICM_DEV_INFO_T* pdev)
{
    int i;
    ICM_INFO_T *picm = NULL;
    int exit_code = EXIT_SUCCESS;
    ICM_CONFIG_T* pconf = &pdev->conf;

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "%s\n", __func__);
    
    for (i = 0; i < MAX_DEV_NUM; i++) {
        picm = get_picm(i);
        if (icm_cleanup_scanner_thread(picm) == FAILURE) {
            exit_code = EXIT_FAILURE;
        }

        if (icm_cleanup_chanset_thread(picm) == FAILURE) {
            exit_code = EXIT_FAILURE;
        }
    }

    for (i = 0; i < MAX_DEV_NUM; i++) {
        if (IS_DEV_ACTIVE(pdev, i)) {
            picm = &pdev->icm[i];
            icm_set_icm_active(picm, 0);
        }
    }

    icm_cleanup_socket(pdev);
    icm_deinit_event_mechanism(pdev);
    
    if (pconf->enable_seldbg_dump) {
        icm_deinit_seldbg_dump(pdev);
    }

    if (pconf->seldbg_filename != NULL) {
        free(pconf->seldbg_filename);
        pconf->seldbg_filename = NULL;
    }

    exit(exit_code);
}


/*
 * Function     : signal_handler
 * Description  : handle user/system generated signal
 * Input params : type of signal
 * Return       : void
 *
 */
void signal_handler(int signal)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    switch(signal) {
        case SIGHUP:
        case SIGTERM:
        case SIGINT:
            icm_cleanup(pdev);
            break;
        case SIGALRM:
            alarm_handler(pdev);
            break;
    }
}

/*
 * Function     : usage
 * Description  : print usage information
 * Input params : user args
 * Return       : success/failure
 *
 */
void print_usage(void)
{
    printf("icm - usage\n");
    printf(LINESTR);
    printf("Options:\n");
    printf("e : run as daemon\n");
    printf("f : use nominal noisefloor\n");
    printf("h : display help\n");
    printf("s : socket type <0(tcp)/1(udp)>\n");
    printf("t : run tests\n");
    printf("v : server mode\n");
    printf("i : dump selection debug information (file: %s)\n",
           DEFAULT_SELDBG_FILENAME);
    printf("q : debug level <1(Minor)/2(Default)/3(Major)/4(Critical))>\n");
    printf("u : debug module bitmap, formed by ORing following \n"
           "    bit positions, each corresponding to a module:\n"
           "    <0x01(Main),      0x02(Scan), 0x04(Selector),\n"
           "     0x08(Utilities), 0x10(Test), 0x20(Socket),\n"
           "     0x40(Spectral),  0x80(Command)>\n");
    printf(LINESTR);

    exit(0);
}

/*
 * Function     : daemonize
 * Description  :
 * Input params :
 * Return       :
 *
 */
void daemonize()
{

    int i = 0;

    /* check if we are already a daemon */
    if (getppid() == 1)
        return;

    i = fork();

    if (i < 0) {
        /* fork error */
        exit(EXIT_FAILURE);
    }

    if (i > 0) {
        /* parent exist */
        exit(0);
    }

    /* child (daemon) continues */
    /* obtain a new process group */
    setsid();

    /* close all descriptors */
    for (i = getdtablesize(); i >= 0; --i) {
        close(i);
    }

    /* set newly created file permissions */
    umask(027);

    signal(SIGCHLD, SIG_IGN);   /* ignore child */
    signal(SIGTSTP, SIG_IGN);   /* ignore try signals */
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);

}



/*
 * Function     : alarm_handler
 * Description  : handles the timer signal, this is used to schedule the
 *                channel swith and start spectral scan
 * Input params : pointer to icm
 * Return       : void
 *
 */
void alarm_handler(ICM_DEV_INFO_T *pdev)
{
    ICM_INFO_T* picm = NULL;

    /*disable the timer */

    alarm(0);

    /* XXX - Once we start doing spectral on both bands, we need to replace
       the below mechanism */
    if ((pdev->active_device >= 0) && (pdev->active_device < MAX_DEV_NUM)) {
        picm = &pdev->icm[pdev->active_device];
    } else {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "Invalid device id\n");
        return;
    }

    if (picm->sinfo.spectral_scan_count < MAX_NUM_SPECTRAL_SCAN_COUNT) {
        icm_stop_spectral_scan(picm);
        
        if (icm_restore_spectral_params(picm) != SUCCESS) {
            ICM_DPRINTF(pdev,
                        ICM_PRCTRL_FLAG_NONE,
                        ICM_DEBUG_LEVEL_MAJOR,
                        ICM_MODULE_ID_MAIN,
                        "Error: Could not restore Spectral Scan parameters\n");
            return;
        }

        icm_switch_channel(picm);
        
        if (icm_configure_spectral_params(picm) != SUCCESS) {
            ICM_DPRINTF(pdev,
                        ICM_PRCTRL_FLAG_NONE,
                        ICM_DEBUG_LEVEL_MAJOR,
                        ICM_MODULE_ID_MAIN,
                        "Error: Could not configure required Spectral Scan "
                        "parameters\n");
            return;
        }
        
        start_spectral_scan(picm);
        
        if (picm->current_channel == 1) {
            alarm(picm->sinfo.dwell_interval_short);
        } else {
            alarm(picm->sinfo.dwell_interval);
        }
    } else {
        icm_stop_spectral_scan(picm);
        
        if (icm_restore_spectral_params(picm) != SUCCESS) {
            ICM_DPRINTF(pdev,
                        ICM_PRCTRL_FLAG_NONE,
                        ICM_DEBUG_LEVEL_MAJOR,
                        ICM_MODULE_ID_MAIN,
                        "Error: Could not restore Spectral Scan parameters\n");
        }
        
        icm_send_event(pdev,
                       ICM_EVENT_RECIPIENT_SPECTRAL_LOOP,
                       ICM_EVENT_SPECTRAL_SWEEP_DONE);
        pdev->active_device = INVALID_DEVICE_ID;
        
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "Spectral Scan : Halted\n");
    }
}

/*
 * Function     : icm_init
 * Description  : initialize everything
 * Input params : user args
 * Return       : success/failure
 *
 */
int icm_init(ICM_DEV_INFO_T* pdev)
{
    int status = SUCCESS;
    int i = 0;
    ICM_CONFIG_T* conf = &pdev->conf;
    ICM_INFO_T* picm = NULL;
    sys_ifnames radio_listing;

    /* register signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGCHLD, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    /* init necessary socket components */
    if (icm_init_netlink_socket(pdev) != SUCCESS) {
        exit(EXIT_FAILURE);
    }

    if (icm_init_ioctl_socket(pdev) != SUCCESS) {
        exit(EXIT_FAILURE);
    }

    if (icm_init_rtnetlink_socket(pdev) != SUCCESS) {
        exit(EXIT_FAILURE);
    }

    if (conf->server_mode == TRUE) {
        if (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_TCP) {
            if (icm_init_streaminet_socket(pdev) == FAILURE) {
                exit(EXIT_FAILURE);
            }
        } else if (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_UDP) {
            if (icm_init_dgraminet_socket(pdev) == FAILURE) {
                exit(EXIT_FAILURE);
            }
        } else {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "invalid socket type\n");
            exit(EXIT_FAILURE);
        }
    }

    if (icm_init_event_mechanism(pdev) != SUCCESS) {
        exit(EXIT_FAILURE);
    }

    if (conf->enable_seldbg_dump == 1) {
        if (icm_init_seldbg_dump(pdev) != SUCCESS) {
            exit(EXIT_FAILURE);
        }
    }

	/* auto detect radio interface */
    if (icm_build_radio_listing(&radio_listing) != SUCCESS) {
        err("Could not create radio listing");
        icm_sys_ifnames_deinit(&radio_listing);
        exit(EXIT_FAILURE);
    }

	/* update the no. of radio devices */
    conf->num_radios = radio_listing.curr_size;
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "No. of radio found %d\n", conf->num_radios);

    for (i = 0; i < conf->num_radios; i++) {

        picm = &pdev->icm[i];
        ICM_ASSERT(picm != NULL);

        /* init device and radio interface names */
        picm->dev_index = i;
        picm->band = conf->dev_config[i].band;
        picm->phy_spec = conf->dev_config[i].phy_spec;
        picm->dev_ifname = conf->dev_config[i].dev_ifname?conf->dev_config[i].dev_ifname:DEFAULT_DEV_IFNAME;
        picm->radio_ifname =  conf->dev_config[i].radio_ifname?conf->dev_config[i].radio_ifname:DEFAULT_RADIO_IFNAME;
        picm->def_channel = conf->dev_config[i].def_channel;
        picm->channel_width = conf->dev_config[i].channel_width;
        picm->best_channel = 0;
        picm->get_nominal_nf = conf->get_nominal_nf;

        picm->usage_factor_80_bw40 = ICM_DEFAULT_USAGE_FACTOR_80_BW40;
        picm->usage_factor_80_bw80 = ICM_DEFAULT_USAGE_FACTOR_80_BW80;

        picm->usage_factor_160_bw40 = ICM_DEFAULT_USAGE_FACTOR_160_BW40;
        picm->usage_factor_160_bw80 = ICM_DEFAULT_USAGE_FACTOR_160_BW80;
        picm->usage_factor_160_bw160 = ICM_DEFAULT_USAGE_FACTOR_160_BW160;

        picm->usage_factor_80p80_bw40 = ICM_DEFAULT_USAGE_FACTOR_80p80_BW40;
        picm->usage_factor_80p80_bw80 = ICM_DEFAULT_USAGE_FACTOR_80p80_BW80;

        if (icm_init_radio_iface(picm, radio_listing.ifnames[i]) != SUCCESS) {
            err("Could not initilize the radio interface");
            icm_sys_ifnames_deinit(&radio_listing);
            exit(EXIT_FAILURE);
        }
        if(picm->numdevs == 0) {
            continue;
        }
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "Radio address for %s = %02X:%02X:%02X:%02X:%02X:%02X\n",
             picm->radio_ifname,
             picm->radio_addr[0],
             picm->radio_addr[1],
             picm->radio_addr[2],
             picm->radio_addr[3],
             picm->radio_addr[4],
             picm->radio_addr[5]);

        ICM_ASSERT(picm->dev_ifname != NULL);
        ICM_ASSERT(picm->radio_ifname != NULL);

        icm_init_scan_params(picm);

        if (icm_init_spectral(picm) != SUCCESS) {
            status = FAILURE;
        }

        icm_set_icm_active(picm, 1);
        icm_init_channel_params(picm);

        picm->substate = ICM_STATE_INVALID;
        picm->ch_selection_mode = ICM_CH_SELECTION_MODE_AUTO;

        /* Init scan job thread */
        if (icm_init_scanner_thread(picm) == FAILURE) {
            icm_sys_ifnames_deinit(&radio_listing);
            exit(EXIT_FAILURE);
        }

        /* Init scan job thread */
        if (icm_init_chanset_thread(picm) == FAILURE) {
            icm_sys_ifnames_deinit(&radio_listing);
            exit(EXIT_FAILURE);
        }

        picm->main_list.head = NULL;
        picm->main_list.tail = NULL;
        picm->repeat_list.head = NULL;
        picm->repeat_list.tail = NULL;

        picm->scan_config.scan_type = 0;
        picm->scan_config.scan_type |= ICM_SCAN_TYPE_CHANNEL_SCAN;
        picm->scan_config.scan_type |= ICM_SCAN_TYPE_SPECTRAL_SCAN;

        if (status) {
            SET_DEV_ACTIVE(pdev, i);
        } else {
            CLR_DEV_ACTIVE(pdev, i);
        }

    }

    return status;
}

/*
 * Function     : icm_config_defaults
 * Description  : initialize the default values
 * Input params :
 * Return       :
 *
 */
static void icm_config_defaults(ICM_CONFIG_T* pconfig)
{
    os_strlcpy(pconfig->dev_config[0].radio_ifname, DEFAULT_ID_0_RADIO_IFNAME, SIZEOF_IFNAME);
    os_strlcpy(pconfig->dev_config[0].dev_ifname, DEFAULT_ID_0_DEV_IFNAME, SIZEOF_IFNAME);

    os_strlcpy(pconfig->dev_config[1].radio_ifname, DEFAULT_ID_1_RADIO_IFNAME, SIZEOF_IFNAME);
    os_strlcpy(pconfig->dev_config[1].dev_ifname, DEFAULT_ID_1_DEV_IFNAME, SIZEOF_IFNAME);

    os_strlcpy(pconfig->dev_config[2].radio_ifname, DEFAULT_ID_2_RADIO_IFNAME, SIZEOF_IFNAME);
    os_strlcpy(pconfig->dev_config[2].dev_ifname, DEFAULT_ID_2_DEV_IFNAME, SIZEOF_IFNAME);

    pconfig->dev_config[0].band = ICM_BAND_INVALID;
    pconfig->dev_config[1].band = ICM_BAND_INVALID;
    pconfig->dev_config[2].band = ICM_BAND_INVALID;

    pconfig->dev_config[0].channel_width = ICM_CH_BW_INVALID;
    pconfig->dev_config[1].channel_width = ICM_CH_BW_INVALID;
    pconfig->dev_config[2].channel_width = ICM_CH_BW_INVALID;

    pconfig->dev_config[0].phy_spec = ICM_PHY_SPEC_INVALID;
    pconfig->dev_config[1].phy_spec = ICM_PHY_SPEC_INVALID;
    pconfig->dev_config[2].phy_spec = ICM_PHY_SPEC_INVALID;

    pconfig->dev_config[0].def_channel = INVALID_CHANNEL;
    pconfig->dev_config[1].def_channel = INVALID_CHANNEL;
    pconfig->dev_config[2].def_channel = INVALID_CHANNEL;

    pconfig->sock_type = SOCK_TYPE_UDP;
    pconfig->run_tests = FALSE;
    pconfig->daemon = FALSE;
    pconfig->server_mode = FALSE;
    pconfig->dbg_level = ICM_DEBUG_LEVEL_DEFAULT;
    pconfig->dbg_module_bitmap = ICM_MODULE_ID_MAIN;
}

/* Start of Attribution: Code taken from QCA apstats */

/*
 * Function     : icm_is_dev_ifname_valid
 * Description  : find if the argument string stands for a valid
 *                device name
 * Input params : string
 * Return       : 1: valid, 0: invalid
 */
int icm_is_dev_ifname_valid(const char *ifname)
{
    int i;
    int basename_len = 0;

    if (ifname == NULL) {
        return 0;
    }

    /* We assume ifname has atleast IFNAMSIZ characters,
       as is the convention for Linux interface names. */

    if (strncmp(ifname, "ath", 3) == 0) {
        basename_len = 3;
    } else if (strncmp(ifname, "wlan", 4) == 0) {
        basename_len = 4;
    } else {
        return 0;
    }

    if (!ifname[basename_len] || !isdigit(ifname[basename_len])) {
        return 0;
    }

    /* We don't make any assumptions on max no. of VAP interfaces,
       at this step. */
    for (i = basename_len + 1; i < IFNAMSIZ; i++)
    {
        if (!ifname[i]) {
            break;
        }

        if (!isdigit(ifname[i])) {
            return 0;
        }
    }

    return 1;
}

/*
 * Function     : icm_is_radio_ifname_valid
 * Description  : find if the argument string stands for a valid
 *                radio name
 * Input params : string
 * Return       : 1: valid, 0: invalid
 */
int icm_is_radio_ifname_valid(const char *ifname)
{
    int i;

    if (ifname == NULL) {
        return 0;
    }

    /* At this step, we only validate if the string makes sense.
       If the interface doesn't actually exist, we'll throw an
       error at the place where we make system calls to try and
       use the interface.
       Reduces the no. of ioctl calls. */

    if (strncmp(ifname, "wifi", 4) != 0) {
        return 0;
    }

    if (!ifname[4] || !isdigit(ifname[4])) {
        return 0;
    }

    /* We don't make any assumptions on max no. of radio interfaces,
       at this step. */
    for (i = 5; i < IFNAMSIZ; i++)
    {
        if (!ifname[i]) {
            break;
        }

        if (!isdigit(ifname[i])) {
            return 0;
        }
    }

    return 1;
}

/*
 * Function     : icm_is_vap_radiochild
 * Description  : Determine if VAP with given H/W address is the child of
 *                radio with given H/W address.
 *                To determine this, we check if the last 5 octets are the same.
 * Input params : MAC address of VAP, MAC address of radio.
 *                It is the caller's responsibility to ensure that the addresses
 *                are correct.
 * Return       : TRUE/FALSE
 */
static bool icm_is_vap_radiochild(const u_int8_t *vapaddr,
                                  const u_int8_t *radioaddr)
{
    if (!memcmp(vapaddr + 1, radioaddr + 1, 5)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

/*
 * Function     : icm_sys_ifnames_init
 * Description  : initialize sys_ifnames structure
 * Input params : pointer to sys_ifnames structure, base max size
 * Return       : 0 on success, standard negative error code on failure
 */
static int icm_sys_ifnames_init(sys_ifnames *ifs, int base_max_size)
{
    int i;

    if (ifs == NULL) {
        return -EINVAL;
    }

    ifs->ifnames = (char**)malloc(base_max_size * sizeof(char*));
    if(!(ifs->ifnames)) {
        return -ENOMEM;
    }

    ifs->curr_size = 0;
    ifs->max_size = 0;

    for (i = 0; i < base_max_size; i++) {
        ifs->ifnames[i] = (char*)malloc(IFNAMSIZ * sizeof(char));
        if (!(ifs->ifnames[i])) {
            /* The caller must call icm_sys_ifnames_deinit() */
            return -1;
        }
        ifs->max_size += 1;
    }

    return 0;
}

/*
 * Function     : icm_sys_ifnames_extend
 * Description  : extend sys_ifnames structure
 * Input params : pointer to sys_ifnames structure, additional max size
 * Return       : 0 on success, standard negative error code on failure
 */
static int icm_sys_ifnames_extend(sys_ifnames *ifs, int additional_size)
{
    int i;
    char **tempptr;

    if (ifs == NULL) {
        return -EINVAL;
    }

    tempptr = (char**)realloc(ifs->ifnames,
                              (ifs->max_size + additional_size) * sizeof(char *));

    if(!tempptr) {
        /* Original block untouched */
        /* The caller must call icm_sys_ifnames_deinit() */
        return -ENOMEM;
    }

    ifs->ifnames = tempptr;

    for (i = ifs->max_size; i < (ifs->max_size + additional_size); i++) {
        ifs->ifnames[i] = (char*)malloc(IFNAMSIZ * sizeof(char));

        if (!(ifs->ifnames[i])) {
            /* The caller must call icm_sys_ifnames_deinit() */
            return -ENOMEM;
        }
        ifs->max_size += 1;
    }

    return 0;
}

/*
 * Function     : icm_sys_ifnames_deinit
 * Description  : de-initialize sys_ifnames structure
 * Input params : pointer to sys_ifnames structure
 */
static void icm_sys_ifnames_deinit(sys_ifnames *ifs)
{
    int i;

    if (ifs == NULL) {
        return;
    }

    if (!ifs->ifnames) {
        return;
    }

    for (i = 0; i < ifs->max_size; i++) {
        free(ifs->ifnames[i]);
    }

    free(ifs->ifnames);
    ifs->ifnames = NULL;
    ifs->max_size = 0;
    ifs->curr_size = 0;
}

/*
 * Function     : icm_sys_ifnames_add
 * Description  : add an interface name to sys_ifnames structure
 * Input params : pointer to sys_ifnames structure, interface name
 * Return       : 0 on success, standard negative error code on failure
 */
static int icm_sys_ifnames_add(sys_ifnames *ifs, char *ifname)
{
   int tempidx = 0;

   if (ifs->curr_size == ifs->max_size) {
        // Full
        return -ENOMEM;
   }

   tempidx = ifs->curr_size;
   if (strlcpy(ifs->ifnames[tempidx], ifname, IFNAMSIZ) >= IFNAMSIZ) {
       fprintf(stderr, "ifname too long: %s\n", ifname);
       return -1;
   }
   ifs->curr_size++;

   return 0;
}

/*
 * Function     : icm_build_vap_listing
 * Description  : build VAP listing for current system, into sys_ifnames structure
 * Input params : pointer to sys_ifnames structure
 * Return       : success/failure
 */
static int icm_build_vap_listing(sys_ifnames *vap_listing)
{
    FILE *fp;
    int i = 0, j = 0;
    char buf[512];
    char temp_name[IFNAMSIZ];
    int ret;
    int status = FAILURE;

    fp = fopen(PATH_PROCNET_DEV, "r");

    if (NULL == fp) {
        perror("icm : " PATH_PROCNET_DEV);
        return FAILURE;
    }

    /* Skip unwanted lines */
    fgets(buf, sizeof(buf), fp);
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp))
    {
        i = 0;
        j = 0;

        while (j < (IFNAMSIZ - 1) && buf[i] != ':') {
            if (isalnum(buf[i])) {
                temp_name[j] = buf[i];
                j++;
            }
            i++;
        }
        temp_name[j] = '\0';

        if (icm_is_dev_ifname_valid(temp_name)) {
            ret = icm_sys_ifnames_add(vap_listing, temp_name);

            if (ret < 0) {
                ret = icm_sys_ifnames_extend(vap_listing, 10);

                if (ret < 0)
                {
                    err("Could not extend ifnames allocation");
                    goto bad;
                }

                ret = icm_sys_ifnames_add(vap_listing, temp_name);

                if (ret < 0)
                {
                    err("Could not add to ifnames");
                    goto bad;
                }
            }
        }
    }

    status = SUCCESS;

bad:
    fclose(fp);
    return status;
}

/*
 * Function     : icm_is_dev_ifname_present
 * Description  : validate if the given device interface name
 *                is a valid VAP on the system, and falls
 *                under the radio for the given icm
 * Input params : pointer to icm info, device interface name
 * Output param : pointer to bool which will contain value
 *                TRUE/FALSE, upon success
 * Return       : success/failure
 */
int icm_is_dev_ifname_present(ICM_INFO_T* picm,
                              char *dev_ifname,
                              bool *ispresent)
{
    int status = FAILURE;
    int i;
    u_int8_t vapaddr[MAX_ADDR_LEN];
    ICM_DEV_INFO_T* pdev = get_pdev();
    sys_ifnames vap_listing;

    *ispresent = FALSE;

    if (icm_sys_ifnames_init(&vap_listing, EXPECTED_MAX_VAPS) < 0) {
        err("Could not initialize VAP listing");
        return FAILURE;
    }

    if (icm_build_vap_listing(&vap_listing) != SUCCESS) {
        err("Could not create VAP listing");
        goto bad;
    }

    for (i = 0; i < vap_listing.curr_size; i++ )
    {
        if (!strncmp(dev_ifname, vap_listing.ifnames[i], IFNAMSIZ)) {
            break;
        }
    }

    if (i == vap_listing.curr_size) {
        goto out;
    }

    if (icm_get_iface_addr(pdev,
                           dev_ifname,
                           vapaddr) != SUCCESS) {
        err("Could not get address of VAP");
        goto bad;
    }

    if (icm_is_vap_radiochild(vapaddr,
                              picm->radio_addr)) {
        *ispresent = TRUE;
    }

out:
    status = SUCCESS;

bad:
    icm_sys_ifnames_deinit(&vap_listing);
    return status;
}


/* End of Attribution: Code taken from QCA apstats */


/*
 * Function     : icm_config_read
 * Description  : read the config data from config file
 * Input params : configuration file with path if needed
 * Return       : config data structure
 *
 */
static int icm_config_read(ICM_DEV_INFO_T* pdev, const char* fname)
{
    ICM_CONFIG_T* conf = NULL;
    FILE *f = NULL;
    char buf[256] = {'\0'};
    char *pos = NULL;
    int line = 0;
    int errors = 0;

    /* get the config data */
    conf = &pdev->conf;

    /* open the config file */
    f = fopen(fname, "r");

    if (f == NULL) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "cannot open config file '%s' for reading\n", fname);
        return -1;
    }

    /* initialize the configuration to default values */
    icm_config_defaults(&pdev->conf);

    /* read the config params */
    while (fgets(buf, sizeof(buf), f)) {

        line++;

        if (buf[0] == '#')
            continue;

        pos = buf;

        while(*pos != '\0') {
            if (*pos == '\n') {
                *pos = '\0';
                break;
            }
            pos++;
        }

        if (buf[0] == '\0')
            continue;

        pos = os_strchr(buf, '=');

        if (pos == NULL) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "line %d: invalid line '%s'\n", line, buf);
            errors++;
            continue;
        }

        *pos = '\0';
        pos++;

        if (os_strcmp(buf, "daemon") == 0) {
            conf->daemon = atoi(pos);
        } else if (os_strcmp(buf, "server_mode") == 0) {
            conf->server_mode = atoi(pos);
        } else if (os_strcmp(buf, "enable_seldbg_dump") == 0) {
            conf->enable_seldbg_dump = atoi(pos);
        } else if(os_strcmp(buf, "debug_level") == 0) {
			conf->dbg_level = atoi(pos);
        } else if (os_strcmp(buf, "debug_module_bitmap") == 0) {
            conf->dbg_module_bitmap = atoi(pos);
        }
    }
    return 0;
}

/*
 * Function     : icm_calculate_fdmax
 * Description  : helper function to calculate required value of
 *                fdmax for select() operation
 * Input params : pointer to pdev info, fd for events, fd for spectral netlink,
 *                fd for server's listen operations
 * Return       : value of fdmax
 */
static int icm_calculate_fdmax(ICM_DEV_INFO_T* pdev,
                               int eventfd,
                               int nlfd,
                               int serverfd)
{
    int fdmax = -1;

    fdmax = eventfd > nlfd ? eventfd : nlfd;

    if (pdev->conf.server_mode == TRUE && fdmax < serverfd) {
        fdmax =  serverfd;
    }

    return fdmax;
}

/*
 * Function     : main
 * Description  : entry point for icm
 * Input params : user args
 * Return       : success/failure
 *
 */
int main(int argc, char* argv[])
{

    int i = 0;
    int ret = 0;
    int evret = 0;
    int optc;
    int fdmax;
    int fd = 0;
    char* config_file = NULL;
    ICM_CONFIG_T* pconf = NULL;
    fd_set master;
    fd_set read_fds;
    int eventfd = -1;
    int netlinkfd = -1;
    ICM_INFO_T* picm;
    bool setchannel = FALSE;

    ICM_INET_T* pinet = NULL;
    ICM_NLSOCK_T* pnlinfo = NULL;
    ICM_NLSOCK_T* prtnlinfo = NULL;

    ICM_EVENT_T event = ICM_EVENT_INVALID;

    pdev->state = ICM_STATE_INITIALIZING;

    /* init pcm data structure */
    for (i = 0; i < MAX_DEV_NUM; i++) {
        picm = get_picm(i);
        memset(picm, 0, sizeof(ICM_INFO_T));
    }

    pconf = &pdev->conf;

    /* initialize default values */
    icm_config_defaults(pconf);

    /* generla init */
    config_file = (config_file)?(config_file):DEFAULT_CONFIG_FILE;
    icm_config_read(pdev, config_file);

    /* extract the user arguments */
    while((optc = getopt(argc, argv, "efhis:tvq:u:")) != -1) {
        switch (optc) {
            case 'e':
                pconf->daemon = TRUE;
                break;
            case 'f':
                pconf->get_nominal_nf = TRUE;
                break;
            case 'q':
				if (!icm_is_debuglevel_valid(optarg)) {
                    fprintf(stderr, "Invalid value %s for debug level.\n",
                            optarg);
                    print_usage();
                    exit(EXIT_FAILURE);
                }
				pconf->dbg_level = atoi(optarg);
				break;
            case 'u':
				if (!icm_is_modulebitmap_valid(optarg)) {
                    fprintf(stderr, "Invalid value %s for dbg_module_bitmap.\n",
                            optarg);
                    print_usage();
                    exit(EXIT_FAILURE);
                }
                pconf->dbg_module_bitmap = atoi(optarg);
                break;
            case 'h':
                print_usage();
                break;
            case 'i':
                pconf->enable_seldbg_dump = 1;
                pconf->seldbg_filename =
                    (char*)malloc(sizeof(char) *
                                  (strlen(DEFAULT_SELDBG_FILENAME) + 1));
                if (pconf->seldbg_filename == NULL) {
                    fprintf(stderr, "Could not allocate memory for selection "
                                    "information dump file.\n");
                    exit(EXIT_FAILURE);
                }
                if (strlcpy(pconf->seldbg_filename, DEFAULT_SELDBG_FILENAME, strlen(DEFAULT_SELDBG_FILENAME) + 1) 
                                >= strlen(DEFAULT_SELDBG_FILENAME) + 1) {
                    fprintf(stderr, "DEFAULT_SELDBG_FILENAME too long: %s\n", DEFAULT_SELDBG_FILENAME);
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                pconf->sock_type = atoi(optarg);
                break;
            case 't':
                pconf->run_tests = TRUE;
                break;
            case 'v':
                pconf->server_mode = TRUE;
                break;
            case '?':
                if ((optopt == 'n') ||
                    (optopt == 'c') ||
                    (optopt == 'd') ||
                    (optopt == 'i') ||
                    (optopt == 'j') ||
                    (optopt == 'k') ||
                    (optopt == 'l') ||
                    (optopt == 'o') ||
                    (optopt == 'p') ||
                    (optopt == 's') ||
                    (optopt == 'w') ||
                    (optopt == 'x')) {
                    fprintf(stderr, "option -%c requires argument.\n", optopt);
                } else {
                    fprintf(stderr, "unknown option '-%c'\n", optopt);
                }
                exit(EXIT_FAILURE);
            default:
                fprintf(stderr, "unknown option '-%c'\n", optopt);
                print_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    init_classifier_lookup_tables();

    if (icm_init(pdev) != SUCCESS) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "icm init failed\n");
        exit(EXIT_FAILURE);
    }

    icm_print_dev_info(pdev);

    if (pconf->daemon) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "Running as daemon\n");
        daemonize();
    }


    /* if enabled, run tests */
    if (pconf->run_tests) {
       for (i = 0; i < pconf->num_radios; i++) {
          picm = get_picm(i);
          icm_do_test(picm);
       }
       icm_cleanup(pdev);
       return 0;
    }

    for (i = 0; i < pconf->num_radios; i++) {
        picm = get_picm(i);
        if(picm->numdevs == 0) {
            continue;
        }

        if (pconf->server_mode == FALSE) {
            setchannel = (picm->def_channel == 0) ? TRUE:FALSE;
            if (icm_scan_and_select_channel(picm, setchannel) !=
                    ICM_SCAN_SELECT_STATUS_SUCCESS) {
                exit(EXIT_FAILURE);
            }
        } else {
            /* We only initialize the selector. Scan and best
               channel selection will be done as per instructions
               from external entity */
            if (icm_selector_init(picm) != SUCCESS) {
                exit(EXIT_FAILURE);
            }
        }
    }

    pinet = ICM_GET_ADDR_OF_INETINFO(pdev);
    pnlinfo = ICM_GET_ADDR_OF_NLSOCK_INFO(pdev);
    prtnlinfo = ICM_GET_ADDR_OF_RTNLSOCK_INFO(pdev);

    eventfd = icm_register_event_recipient(pdev,
                                           ICM_EVENT_RECIPIENT_MAIN);

    if (eventfd == -1) {
        err("Could not register for event reception");
        exit(EXIT_FAILURE);
    }

    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(pnlinfo->sock_fd, &master);
    FD_SET(prtnlinfo->sock_fd, &master);
    FD_SET(eventfd, &master);

    if (pconf->server_mode == TRUE) {
        FD_SET(pinet->listener, &master);
    }

	/* selecting the max netlink fd */
    netlinkfd = (pnlinfo->sock_fd > prtnlinfo->sock_fd) ? pnlinfo->sock_fd : prtnlinfo->sock_fd;
    fdmax = icm_calculate_fdmax(pdev,
                                eventfd,
                                netlinkfd,
                                pinet->listener);

    pdev->state = ICM_STATE_IDLE;

    for (;;) {
        read_fds = master;

        ret = select(fdmax + 1, &read_fds, NULL, NULL, NULL);

        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            } else {
                perror("icm : select");
                exit(EXIT_FAILURE);
            }
        }

        for (fd = 0; fd <= fdmax; fd++) {
            if (FD_ISSET(fd, &read_fds)) {
                if (fd == eventfd) {
                    evret = icm_get_event(pdev,
                                          ICM_EVENT_RECIPIENT_MAIN,
                                          &event);

                    if (evret != SUCCESS) {
                        err("Error retrieving event");
                        continue;
                    }

                    switch(event) {
                        case ICM_EVENT_SCAN_JOB_DONE:
                            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "Received Scan Job Done event\n");
                            break;
                        case ICM_EVENT_SPECTRAL_SWEEP_STARTED:
                            FD_CLR(pnlinfo->sock_fd, &master);
                            fdmax = icm_calculate_fdmax(pdev,
                                                        eventfd,
                                                        -1,
                                                        pinet->listener);
                            break;
                         case ICM_EVENT_SPECTRAL_SWEEP_DONE:
                            FD_SET(pnlinfo->sock_fd, &master);
                            fdmax = icm_calculate_fdmax(pdev,
                                                        eventfd,
                                                        pnlinfo->sock_fd,
                                                        pinet->listener);
                            break;
                         default:
                            err("Unhandled event received");
                            break;
                    }
                } else if (fd == pnlinfo->sock_fd) {
                    if (icm_handle_spectral_data(pdev, NULL) == FAILURE) {
                        icm_cleanup(pdev);
                        exit(EXIT_FAILURE);
                    }
				} else if (fd == prtnlinfo->sock_fd) {
						ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Received device state change event \n");
						if(icm_parse_rtnetlink_msg(pdev) == FAILURE) {
                            icm_cleanup(pdev);
                            exit(EXIT_FAILURE);
                        }
                } else if (pconf->server_mode == TRUE) {
                    if (fd == pinet->listener) {
                        if (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_UDP) {
                            if (icm_handle_client_data(pdev, fd) == -1) {
                                icm_cleanup(pdev);
                                exit(EXIT_FAILURE);
                            }
                        } else if (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_TCP) {
                            if (icm_accept_new_connection(pdev)) {
                                FD_SET(pinet->client_fd, &master);
                                fdmax = (pinet->client_fd > fdmax)? \
                                    pinet->client_fd:fdmax;
                            }
                        }
                    } else if ((fd == pinet->client_fd) &&
                               (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_TCP)) {
                        if (icm_handle_client_data(pdev, fd) == -1) {
                            icm_cleanup(pdev);
                            exit(EXIT_FAILURE);
                        }
                    }
                }
            }
        }
    }

    /* do cleanup */
    icm_cleanup(pdev);
    return 0;
}

/* Channel Set thread */

/*
 * Function     : icm_init_chanset_thread
 * Description  : initialize channel set thread
 * Input params : pointer to icm
 * Return       : SUCCESS/FAILURE
 */
int icm_init_chanset_thread(ICM_INFO_T *picm)
{
    int ret = 0;

    if ((ret = pthread_attr_init(&picm->chanset_thread_attr)) < 0) {
        perror("icm : pthread_attr_init");
        return FAILURE;
    }

    if ((ret = pthread_attr_setdetachstate(&picm->chanset_thread_attr,
                                           PTHREAD_CREATE_DETACHED)) < 0) {
        perror("icm : pthread_attr_setdetachstate");
        return FAILURE;
    }

    if ((ret = pthread_mutex_init(&picm->chanset_thread_mutex,
                                  NULL)) < 0) {
        perror("icm : pthread_mutex_init");
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_cleanup_chanset_thread
 * Description  : de-initialize channel set thread
 * Input params : pointer to icm
 * Return       : SUCCESS/FAILURE
 */
int icm_cleanup_chanset_thread(ICM_INFO_T *picm)
{
    int ret = 0;
    int status = SUCCESS;

    if (icm_is_chanset_thread_active(picm) == TRUE) {
        if ((ret = pthread_cancel(picm->chanset_thread)) < 0) {
            status = FAILURE;
        }
    }

    /* TODO: Handle all cancellation procedures */

    icm_set_chanset_thread_active(picm, FALSE);

    if ((ret = pthread_attr_destroy(&picm->chanset_thread_attr)) < 0) {
        perror("icm : pthread_attr_destroy");
        status = FAILURE;
    }

    if ((ret = pthread_mutex_destroy(&picm->chanset_thread_mutex)) < 0) {
        perror("icm : pthread_mutex_destroy");
        return FAILURE;
    }

    return status;
}

/*
 * Function     : icm_set_chanset_thread_active
 * Description  : set whether channel set thread is active
 * Input params : pointer to icm
 * Return       : TRUE/FALSE
 */
void icm_set_chanset_thread_active(ICM_INFO_T *picm, bool value)
{
    pthread_mutex_lock(&picm->chanset_thread_mutex);
    picm->is_chanset_thread_active = value;
    pthread_mutex_unlock(&picm->chanset_thread_mutex);
}

/*
 * Function     : icm_is_chanset_thread_active
 * Description  : report whether channel set thread is active
 * Input params : pointer to icm
 * Return       : TRUE/FALSE
 */
bool icm_is_chanset_thread_active(ICM_INFO_T *picm)
{
    bool value = FALSE;

    pthread_mutex_lock(&picm->chanset_thread_mutex);
    value = picm->is_chanset_thread_active;
    pthread_mutex_unlock(&picm->chanset_thread_mutex);

    return value;
}

/*
 * Function     : icm_activate_chanset_thread
 * Description  : activate channel set thread to perform a scan job
 * Input params : pointer to icm
 * Return       : SUCCESS/FAILURE
 */
int icm_activate_chanset_thread(ICM_INFO_T *picm)
{
    int pret = 0;

    if (icm_is_chanset_thread_active(picm) == TRUE) {
        return FAILURE;
    }

    pret = pthread_create(&picm->chanset_thread,
                          &picm->chanset_thread_attr,
                          icm_process_chanset_job,
                          (void*)picm);

    if (pret < 0) {
        perror("icm : pthread_create");
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_chanset_ll_add
 * Description  : add a channel set job at tail of linked list
 * Input params : pointer to icm,
 *                pointer to channel set job linked list,
 *                pointer to channel set job
 */
void icm_chanset_ll_add(ICM_INFO_T *picm,
                        ICM_CHANSET_JOB_LL_T *list,
                        ICM_CHANSET_JOB_T *chanset)
{
    if (picm == NULL || list == NULL || chanset == NULL) {
        return;
    }

    /* Note that this is a quick and simple implementation for readability
       since this is sparsely used and thus not space/performance critical. */

    pthread_mutex_lock(&picm->chanset_thread_mutex);

    if (list->tail == NULL) {
        /* Empty */
        list->tail = chanset;
        list->head = chanset;
        chanset->next = NULL;
        chanset->prev = NULL;
    } else {
        chanset->next = list->tail;
        chanset->prev = NULL;
        list->tail->prev = chanset;
        list->tail = chanset;
    }

    pthread_mutex_unlock(&picm->chanset_thread_mutex);
    return;
}

/*
 * Function     : icm_chanset_ll_del
 * Description  : remove a channel set job from head of linked list
 * Input params : pointer to icm,
 *                pointer to channel set job linked list
 * Return       : pointer to channel set job or NULL if empty
 */
ICM_CHANSET_JOB_T* icm_chanset_ll_del(ICM_INFO_T *picm,
                                      ICM_CHANSET_JOB_LL_T *list)
{
    ICM_CHANSET_JOB_T *chanset = NULL;

    if (picm == NULL) {
        return NULL;
    }

    /* Note that this is a quick and simple implementation for readability
       since this is sparsely used and thus not space/performance critical. */

    pthread_mutex_lock(&picm->chanset_thread_mutex);

    if (list->head == NULL) {
        pthread_mutex_unlock(&picm->chanset_thread_mutex);
        return NULL;
    }

    chanset = list->head;

    if (list->head == list->tail) {
        /* Last element */
        list->head = list->tail = NULL;
    } else {
        list->head = list->head->prev;
        list->head->next = NULL;
    }

    /* Not really necessary, but for cleanliness */
    chanset->next = NULL;
    chanset->prev = NULL;

    pthread_mutex_unlock(&picm->chanset_thread_mutex);
    return chanset;
}

/*
 * Function     : icm_has_chanset_expired
 * Description  : find whether a channel set job has expired
 * Input params : pointer to icm, pointer to channel set job
 * Out params   : pointer to bool indicating whether channel
 *                set job has expired (valid only on SUCCESS)
 * Return       : SUCCESS/FAILURE
 */
static int icm_has_chanset_expired(ICM_INFO_T *picm,
                                   ICM_CHANSET_JOB_T *chanset,
                                   bool *hasexpired)
{
    struct timeval currtime;

    memset(&currtime, 0, sizeof(currtime));

    *hasexpired = FALSE;

    if (gettimeofday(&currtime, NULL) < 0) {
        perror("icm : gettimeofday");
        return FAILURE;
    }

    if (timercmp(&chanset->timeout, &currtime, <)) {
        *hasexpired = TRUE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_is_dev_up
 * Description  : find whether a device is up
 * Input params : pointer to ICM_DEV_INFO_T, device name
 * Out params   : pointer to bool indicating whether device is
                  up (valid only on SUCCESS)
 * Return       : SUCCESS/FAILURE
 */
static int icm_is_dev_up(ICM_DEV_INFO_T* pdev,
                         char *dev_ifname,
                         bool *isup)
{
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);
    struct ifreq ifr;

    *isup = FALSE;

    if (strlcpy(ifr.ifr_name, dev_ifname, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "dev_ifname too long: %s\n", dev_ifname);
        return FAILURE;
    }

    if (ioctl(iocinfo->sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("icm : ioctl");
        return FAILURE;
    }

    if (ifr.ifr_flags & IFF_UP) {
        *isup = TRUE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_is_dev_ap
 * Description  : find whether a device is in AP mode
 * Input params : pointer to ICM_DEV_INFO_T, device name
 * Out params   : pointer to bool indicating whether device is
                  in AP mode (valid only on SUCCESS)
 * Return       : SUCCESS/FAILURE
 */
static int icm_is_dev_ap(ICM_DEV_INFO_T* pdev,
                         char *dev_ifname,
                         bool *isap)
{
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);
    struct iwreq iwr;

    *isap = FALSE;

    if (strlcpy(iwr.ifr_name, dev_ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
        fprintf(stderr, "dev_ifname too long: %s\n", dev_ifname);
        return FAILURE;
    }

    if (ioctl(iocinfo->sock_fd, SIOCGIWMODE, &iwr) < 0) {
        perror("icm : ioctl");
        return FAILURE;
    }

    if (iwr.u.mode > IW_MODE_MESH) {
        err("Unknown mode");
        return FAILURE;
    }

    if (iwr.u.mode == IW_MODE_MASTER) {
        *isap = TRUE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_set_width_and_channel
 * Description  : set width and channel as per best channel
 *                selection done previously.
 *                It is the caller's responsibility to ensure
 *                that the best channel selection has already been
 *                carried out, or if this has not been done, then
 *                a default channel has been set instead.
 *                It is the best channel selection code's
 *                responsibility to ensure that the width and channel
 *                are correct.
 * Input params : pointer to icm info, device name
 * Return       : SUCCESS/FAILURE
 */
int icm_set_width_and_channel(ICM_INFO_T *picm, char *dev_ifname)
{
    char cmd[CMD_BUF_SIZE] = {'\0'};
    char modestr[24] = {'\0'};
    int ret = 0;
    ICM_CH_BW_T channel_width;
    int channel = 0;
    int cfreq2_channel = 0;
    ICM_DEV_INFO_T* pdev = get_pdev();
    channel_width = picm->channel_width;
    if (picm->ch_selection_mode == ICM_CH_SELECTION_MODE_MANUAL) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "In manual channel selection mode; using default channel\n");
        channel = picm->def_channel;
    } else if (picm->best_channel <= 0) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Best channel not set/invalid. Considering "
             "default channel instead.\n");

        if (picm->def_channel == 0) {
            err("Both best channel and default channel are not set/invalid");
            return FAILURE;
        }

        channel = picm->def_channel;
    } else {
        channel = picm->best_channel;

        /* We are operating in auto mode, so we need to use the resolved
           channel width. Without doing so, we won't properly set the
           mode in the case we have to resort to 20 MHz fallback
           or we selected plus/minus from the generic 40 MHz mode. */
        channel_width = picm->selected_channel_width;
    }

    /* Set mode */

    if (channel_width >= ICM_CH_BW_INVALID) {
        err("Invalid channel width enumeration %u", channel_width);
        return FAILURE;
    }

    if (channel_width == ICM_CH_BW_80_PLUS_80) {
        /* XXX Add default channel processing for cfreq2 */
        cfreq2_channel = picm->best_cfreq2_channel;
    }

    if (icm_compose_phymode_str(picm->phy_spec,
                                channel_width,
                                modestr,
                                sizeof(modestr)) == NULL) {
        return FAILURE;
    }

    snprintf(cmd, sizeof(cmd), "%s %s %s %s", "iwpriv",
             dev_ifname, "mode",  modestr);
    ret = system(cmd);

    if (ret == -1) {
        perror("icm : system");
        return FAILURE;
    }

    if (WEXITSTATUS(ret) != 0) {
        err("Error in setting mode; command was: %s", cmd);
        return FAILURE;
    }

    if (channel_width == ICM_CH_BW_80_PLUS_80) {
         /* Set cfreq2 */
        snprintf(cmd, sizeof(cmd), "%s %s %s %1d", "iwpriv",
                 dev_ifname, "cfreq2", icm_convert_ieee2mhz(cfreq2_channel));
        ret = system(cmd);

        if (ret == -1) {
            perror("icm : system");
            return FAILURE;
        }

        if (WEXITSTATUS(ret) != 0) {
            err("Error in setting channel; command was: %s", cmd);
            return FAILURE;
        }
    }

    /* Set channel */
    snprintf(cmd, sizeof(cmd), "%s %s %s %1d", "iwconfig",
             dev_ifname, "channel", channel);
    ret = system(cmd);

    if (ret == -1) {
        perror("icm : system");
        return FAILURE;
    }

    if (WEXITSTATUS(ret) != 0) {
        err("Error in setting channel; command was: %s", cmd);
        return FAILURE;
    }


    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Successfully set channel %d mode %s\n",

         channel,
         modestr);

    if (channel_width == ICM_CH_BW_80_PLUS_80) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Successfully set secondary 80 MHz channel index %d mode %s\n",
             cfreq2_channel,
             modestr);
    }

    return SUCCESS;
}

/*
 * Function     : icm_process_chanset_job
 * Description  : Pthread executable function which processes requested
 *                channel set jobs.
                  Checking to ensure the device name in each channel set job
                  is a valid VAP name is the requester's responsibility.
 * Input params : void pointer pointing to location of an ICM_INFO_T
 *                structure
 * Return       : NULL. The results (including success/failure)
 *                will be stored into the ICM_INFO_T structure.
 *
 */
void* icm_process_chanset_job(void *arg)
{
    ICM_INFO_T *picm = (ICM_INFO_T *)arg;
    ICM_DEV_INFO_T* pdev = get_pdev();
    int ret = 0;
    ICM_CHANSET_JOB_T *chanset;
    int fdmax = 0;
    fd_set master;
    fd_set read_fds;
    struct timeval tv;
    struct timeval tvmaster;
    bool hasexpired = FALSE;
    bool isup = FALSE;
    bool isap = FALSE;
    u_int8_t  devaddr[MAX_ADDR_LEN];
    u_int8_t rsp_status = ICM_RSP_STATUS_FAILURE;
    int send_status = FAILURE;
    int parse_status_cumulative = FAILURE;
    int send_status_cumulative = SUCCESS;
    bool repeat_requested = FALSE;

    pthread_mutex_lock(&picm->chanset_thread_mutex);
    picm->is_chanset_thread_active = TRUE;
    pthread_mutex_unlock(&picm->chanset_thread_mutex);

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "About to start processing requested channel set jobs on radio %s\n",
         picm->radio_ifname);

    picm->chanset_thread_status = FAILURE;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    fdmax = 0;
    tvmaster.tv_sec = 0;
    tvmaster.tv_usec = ICM_CHANSET_POLL_INTERVAL_MS * 1000;
    tv = tvmaster;

    /* For now, we use polling. Later, we can convert to RTMGRP_LINK
       netlink based  asynchronous method after ensuring this
       doesn't break any Hybrid related assumptions/requirements. */

    while(1) {

        read_fds = master;

        /* The probability of devices not being ready on the first try
           is high. So we launch into the select right away */

        ret = select(fdmax + 1, &read_fds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            } else {
                perror("icm : select");
                goto bad;
            }
        }

        if (ret == 0) {
            /* Timeout */

            tv = tvmaster;

            while ((chanset = icm_chanset_ll_del(picm, &picm->main_list))
                    != NULL) {
                /* We could have checked for expiry right at this point,
                   but we provide a bit of grace */
                if (icm_is_dev_up(pdev, chanset->dev_ifname, &isup)
                        != SUCCESS) {
                    err("Could not find if device is up");
                    icm_chanset_ll_add(picm, &picm->main_list, chanset);
                    goto bad;
                }

                 if (!isup) {
                    if (icm_has_chanset_expired(picm, chanset, &hasexpired)
                            != SUCCESS) {
                        err("Could not find if channel set job has expired");
                        icm_chanset_ll_add(picm, &picm->main_list, chanset);
                        goto bad;
                    }

                    if (!hasexpired) {
                        icm_chanset_ll_add(picm, &picm->repeat_list, chanset);
                        continue;
                    } else {
                        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Channel set request transactionId %u expired"
                             " since the AP interface %s is not yet up\n",
                             chanset->transactionId,
                             chanset->dev_ifname);
                        send_status = icm_channel_set_rsp(pdev,
                                                      chanset->transactionId,
                                                      ICM_RSP_STATUS_FAILURE);

                        if (send_status_cumulative == SUCCESS) {
                            send_status_cumulative = send_status;
                        }

                        free(chanset);
                        continue;
                    }
                }

                /* Device is up. Find if it falls under our radio.
                   Checking to ensure the device name is a valid
                   VAP name is the requester's responsibility. */

                if (icm_get_iface_addr(pdev,
                                       chanset->dev_ifname,
                                       devaddr) != SUCCESS) {
                    err("Could not get h/w address of device");
                    icm_chanset_ll_add(picm, &picm->main_list, chanset);
                    goto bad;
                }

                if (!icm_is_vap_radiochild(devaddr,
                                           picm->radio_addr)) {
                    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "deviceName %s sent by peer does not fall under radio %s\n",
                         chanset->dev_ifname,
                         picm->radio_ifname);
                     send_status =
                            icm_channel_set_rsp(pdev,
                                                chanset->transactionId,
                                                ICM_RSP_STATUS_INVALID_PARAM);

                    if (send_status_cumulative == SUCCESS) {
                        send_status_cumulative = send_status;
                    }

                    free(chanset);
                    continue;
                }

                /* Device falls under our radio.
                   Confirm it is in AP mode anyway. */
                if (icm_is_dev_ap(pdev, chanset->dev_ifname, &isap) != SUCCESS) {
                    err("Could not find if device is in AP mode");
                    icm_chanset_ll_add(picm, &picm->main_list, chanset);
                    goto bad;
                }

                if (!isap) {
                    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "deviceName %s sent by peer is not in AP mode\n",
                         chanset->dev_ifname);

                    send_status =
                            icm_channel_set_rsp(pdev,
                                                chanset->transactionId,
                                                ICM_RSP_STATUS_INVALID_PARAM);

                    if (send_status_cumulative == SUCCESS) {
                        send_status_cumulative = send_status;
                    }

                    free(chanset);
                    continue;
                }

                /* Everything checks out. Set mode and channel */
                if (icm_set_width_and_channel(picm, chanset->dev_ifname)
                        != SUCCESS) {
                    err("Could not set channel and mode");
                    send_status =
                            icm_channel_set_rsp(pdev,
                                                chanset->transactionId,
                                                ICM_RSP_STATUS_FAILURE);

                    if (send_status_cumulative == SUCCESS) {
                        send_status_cumulative = send_status;
                    }

                    free(chanset);
                    continue;
                }

                /* Everything worked! */

                send_status = icm_channel_set_rsp(pdev,
                                                  chanset->transactionId,
                                                  ICM_RSP_STATUS_SUCCESS);

                if (send_status_cumulative == SUCCESS) {
                    send_status_cumulative = send_status;
                }

                free(chanset);
            }

            repeat_requested = FALSE;

            /* Add back items on repeat list into main list */
            while ((chanset = icm_chanset_ll_del(picm, &picm->repeat_list))
                    != NULL) {
                icm_chanset_ll_add(picm, &picm->main_list, chanset);
                repeat_requested = TRUE;
            }

            if (!repeat_requested) {
                break;
            }
        }
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Completed all queued channel set jobs on radio %s\n",
         picm->radio_ifname);

    parse_status_cumulative = SUCCESS;
    goto out;

bad:
    rsp_status = ICM_RSP_STATUS_FAILURE;

    /* Purge all requests. */
    while ((chanset = icm_chanset_ll_del(picm, &picm->main_list)) != NULL) {
        send_status = icm_channel_set_rsp(pdev,
                                          chanset->transactionId,
                                          rsp_status);

        if (send_status_cumulative == SUCCESS) {
            send_status_cumulative = send_status;
        }

        free(chanset);
    }

    while ((chanset = icm_chanset_ll_del(picm, &picm->repeat_list)) != NULL) {
        send_status = icm_channel_set_rsp(pdev,
                                          chanset->transactionId,
                                          rsp_status);

        if (send_status_cumulative == SUCCESS) {
            send_status_cumulative = send_status;
        }

        free(chanset);
    }


out:
    if (send_status_cumulative == SUCCESS &&
        parse_status_cumulative == SUCCESS) {
        picm->chanset_thread_status = SUCCESS;
    } else {
        picm->chanset_thread_status = FAILURE;
    }

    pthread_mutex_lock(&picm->chanset_thread_mutex);
    picm->is_chanset_thread_active = FALSE;
    pthread_mutex_unlock(&picm->chanset_thread_mutex);

    pthread_exit(NULL);
}

/*
 * Function     : icm_get_radio_default_channel
 * Description  : This is a wrapper function to get the desired channel for the given VAP.
 * Input params : const char pointer pointing to interface name
 * Return       : Success for valid inteface name
 *				  Failure -1
 *
 */
static int icm_get_radio_default_channel(const char *ifname)
{
	ICM_DEV_INFO_T* pdev = get_pdev();

	if (pdev == NULL) {
		return FAILURE;
	}

	return get_vap_priv_int_param(pdev, ifname, IEEE80211_PARAM_DESIRED_CHANNEL);
}

/*
 * Function     : icm_get_radio_phy_spec
 * Description  : Get phy spec for given VAP
 * Input params : const char pointer pointing to interface name
 * Return       : Success for valid inteface name
 *				  Failure for invalid interface
 *
 */
static int icm_get_radio_phy_spec(const char *ifname)
{
	int phy_spec = 0;
	ICM_DEV_INFO_T* pdev = get_pdev();
	int phymode =  get_vap_priv_int_param(pdev, ifname, IEEE80211_PARAM_DESIRED_PHYMODE);

	switch(phymode) {
    	case IEEE80211_MODE_11A:
			phy_spec = ICM_PHY_SPEC_11A;
			break;
    	case IEEE80211_MODE_11B:
			phy_spec = ICM_PHY_SPEC_11B;
			break;
    	case IEEE80211_MODE_11G:
			phy_spec = ICM_PHY_SPEC_11G;
			break;
    	case IEEE80211_MODE_FH:
			phy_spec = ICM_PHY_SPEC_FH;
			break;
    	case IEEE80211_MODE_TURBO_A:
			phy_spec = ICM_PHY_SPEC_TURBO_A;
			break;
    	case IEEE80211_MODE_TURBO_G:
			phy_spec = ICM_PHY_SPEC_TURBO_G;
			break;

    	case IEEE80211_MODE_11NA_HT20:
    	case IEEE80211_MODE_11NA_HT40PLUS:
    	case IEEE80211_MODE_11NA_HT40MINUS:
    	case IEEE80211_MODE_11NA_HT40:
			phy_spec = ICM_PHY_SPEC_11NA;
            break;

    	case IEEE80211_MODE_11NG_HT20:
    	case IEEE80211_MODE_11NG_HT40PLUS:
    	case IEEE80211_MODE_11NG_HT40MINUS:
    	case IEEE80211_MODE_11NG_HT40:
			phy_spec = ICM_PHY_SPEC_11NG;
            break;

    	case IEEE80211_MODE_11AC_VHT20:
    	case IEEE80211_MODE_11AC_VHT40PLUS:
    	case IEEE80211_MODE_11AC_VHT40MINUS:
    	case IEEE80211_MODE_11AC_VHT40:
    	case IEEE80211_MODE_11AC_VHT80:
    	case IEEE80211_MODE_11AC_VHT160:
    	case IEEE80211_MODE_11AC_VHT80_80:
			phy_spec = ICM_PHY_SPEC_11AC;
            break;

		default:
			phy_spec = ICM_BAND_INVALID;
            break;
	}

	return phy_spec;
}

/*
 * Function     : icm_get_radio_band
 * Description  : Get band for given VAP
 * Input params : value of the phy spec
 * Return       : band for given interface
 *				  Failure for invalid interface
 *
 */
static int icm_get_radio_band(const char *ifname)
{
	int band = 0;
	ICM_DEV_INFO_T* pdev = get_pdev();
	int phymode =  get_vap_priv_int_param(pdev, ifname, IEEE80211_PARAM_DESIRED_PHYMODE);

	switch(phymode) {
    	case IEEE80211_MODE_11B:
    	case IEEE80211_MODE_11G:
    	case IEEE80211_MODE_FH:
    	case IEEE80211_MODE_TURBO_G:
    	case IEEE80211_MODE_11NG_HT20:
    	case IEEE80211_MODE_11NG_HT40PLUS:
    	case IEEE80211_MODE_11NG_HT40MINUS:
    	case IEEE80211_MODE_11NG_HT40:
			band = ICM_BAND_2_4G;
            break;

    	case IEEE80211_MODE_11A:
    	case IEEE80211_MODE_11NA_HT40:
    	case IEEE80211_MODE_TURBO_A:
    	case IEEE80211_MODE_11NA_HT20:
    	case IEEE80211_MODE_11NA_HT40PLUS:
    	case IEEE80211_MODE_11NA_HT40MINUS:
    	case IEEE80211_MODE_11AC_VHT20:
    	case IEEE80211_MODE_11AC_VHT40PLUS:
    	case IEEE80211_MODE_11AC_VHT40MINUS:
    	case IEEE80211_MODE_11AC_VHT40:
    	case IEEE80211_MODE_11AC_VHT80:
    	case IEEE80211_MODE_11AC_VHT160:
    	case IEEE80211_MODE_11AC_VHT80_80:
			band = ICM_BAND_5G;
            break;

		case IEEE80211_MODE_AUTO:
            band = ICM_BAND_INVALID;
            err("automode Currently not supported\n");
            break;
		default:
			band = ICM_BAND_INVALID;
            break;
	}
	return band;
}

/*
 * Function     : icm_get_radio_channel_width
 * Description  : Get channel width for given radio.
 * Input params : value of the phy spec
 * Return       : channel width of given radio
 *                Failure
 *
 */
static int icm_get_radio_channel_width(const char *ifname)
{
	int channel_width = 0;
	ICM_DEV_INFO_T* pdev = get_pdev();
	int phymode =  get_vap_priv_int_param(pdev, ifname, IEEE80211_PARAM_DESIRED_PHYMODE);

	switch(phymode) {
    	case IEEE80211_MODE_11B:
    	case IEEE80211_MODE_11G:
    	case IEEE80211_MODE_FH:
    	case IEEE80211_MODE_TURBO_G:
    	case IEEE80211_MODE_11A:
    	case IEEE80211_MODE_TURBO_A:
    	case IEEE80211_MODE_11NA_HT20:
    	case IEEE80211_MODE_11NG_HT20:
    	case IEEE80211_MODE_11AC_VHT20:
			channel_width = ICM_CH_BW_20;
            break;

    	case IEEE80211_MODE_11NG_HT40PLUS:
    	case IEEE80211_MODE_11NA_HT40PLUS:
    	case IEEE80211_MODE_11AC_VHT40PLUS:
			channel_width = ICM_CH_BW_40PLUS;
            break;

    	case IEEE80211_MODE_11NG_HT40MINUS:
    	case IEEE80211_MODE_11NA_HT40MINUS:
    	case IEEE80211_MODE_11AC_VHT40MINUS:
			channel_width = ICM_CH_BW_40MINUS;
            break;

    	case IEEE80211_MODE_11NG_HT40:
    	case IEEE80211_MODE_11NA_HT40:
    	case IEEE80211_MODE_11AC_VHT40:
			channel_width = ICM_CH_BW_40;
            break;

    	case IEEE80211_MODE_11AC_VHT80:
			channel_width = ICM_CH_BW_80;
            break;

    	case IEEE80211_MODE_11AC_VHT160:
			channel_width = ICM_CH_BW_160;
            break;

    	case IEEE80211_MODE_11AC_VHT80_80:
			channel_width = ICM_CH_BW_80_PLUS_80;
            break;

		case IEEE80211_MODE_AUTO:
			channel_width = ICM_CH_BW_INVALID;
            err("automode Currently not supported\n");
            break;
		default:
			channel_width = ICM_CH_BW_INVALID;
			break;
	}

	return channel_width;
}

/*
 * Function     : icm_build_radio_listing
 * Description  : it automatically detects and lists the radio interfaces.
 * Input params : pointer to the sys_ifnames structure.
 * Return       : Success for sucessful listing of all the radio interface
 *				  Failure
 *
 */
static int icm_build_radio_listing(sys_ifnames *radio_listing)
{
    FILE *fp;
    int i = 0, j = 0;
    char buf[512];
    char temp_name[IFNAMSIZ];
    int ret;
    int status = FAILURE;

    if (icm_sys_ifnames_init(radio_listing, EXPECTED_MAX_VAPS) < 0) {
        err("Could not initialize radio listing");
        return FAILURE;
    }

    fp = fopen(PATH_PROCNET_DEV, "r");

    if (NULL == fp) {
        perror("icm : " PATH_PROCNET_DEV);
        return FAILURE;
    }

    /* Skip unwanted lines */
    fgets(buf, sizeof(buf), fp);
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp))
    {
        i = 0;
        j = 0;

        while (j < (IFNAMSIZ - 1) && buf[i] != ':') {
            if (isalnum(buf[i])) {
                temp_name[j] = buf[i];
                j++;
            }
            i++;
        }
        temp_name[j] = '\0';

        if (icm_is_radio_ifname_valid(temp_name)) {
            ret = icm_sys_ifnames_add(radio_listing, temp_name);

            if (ret < 0) {
                ret = icm_sys_ifnames_extend(radio_listing, 10);

                if (ret < 0)
                {
                    err("Could not extend ifnames allocation");
                    goto bad;
                }

                ret = icm_sys_ifnames_add(radio_listing, temp_name);

                if (ret < 0)
                {
                    err("Could not add to ifnames");
                    goto bad;
                } /* end of inner if (ret < 0)*/
            } /* end of outer if ( ret < 0) */
        } /* end of if(icm_is_radio_ifname_valid())*/
    } /* end of while(fets()) */

    status = SUCCESS;

bad:
    fclose(fp);

    return status;
}

/*
 * Function     : icm_init_radio_iface
 * Description  : it initilize all the devices information for the
 *					given radio automatically
 * Input params : pointer to the ICM_INFO_T structure and char pointer pointing to interface name
 * Return       : Success
 *				  Failure
 *
 */
static int icm_init_radio_iface(ICM_INFO_T* picm, char *radio_ifname)
{
    int status = FAILURE;
    int i;
    u_int8_t radio_addr[MAX_ADDR_LEN];
    u_int8_t vapaddr[MAX_ADDR_LEN];
    u_int8_t numdevs = 0;
    u_int8_t flag = 0;
    bool isap = FALSE;
    ICM_DEV_INFO_T* pdev = get_pdev();
    sys_ifnames vap_listing;

	if (radio_ifname == NULL) {
        return FAILURE;
    }

    if (icm_sys_ifnames_init(&vap_listing, EXPECTED_MAX_VAPS) < 0) {
        err("Could not initialize VAP listing");
        return FAILURE;
    }

    if (icm_build_vap_listing(&vap_listing) != SUCCESS) {
        err("Could not create VAP listing");
        goto bad;
    }

	if (icm_get_iface_addr(pdev, radio_ifname,
        	        radio_addr) != SUCCESS) {
    	err("Could not get address of VAP");
    	goto bad;
    }
    for (i = 0; i < vap_listing.curr_size; i++ )
    {

        if (icm_get_iface_addr(pdev,
                               vap_listing.ifnames[i],
                               vapaddr) != SUCCESS) {
            err("Could not get address of VAP");
            goto bad;
        }
        if (icm_is_vap_radiochild(vapaddr, radio_addr)) {
    		memcpy(picm->dev_ifnames_list[numdevs], vap_listing.ifnames[i], IFNAMSIZ);
            numdevs++;

			if(!flag) {

				if (icm_is_dev_ap(pdev, vap_listing.ifnames[i], &isap) == SUCCESS) {

					if (isap) {
						flag = 1;
						if (strlcpy(picm->dev_ifname, vap_listing.ifnames[i], IFNAMSIZ) >= IFNAMSIZ) {
							fprintf(stderr, "ifname too long: %s\n", vap_listing.ifnames[i]);
							goto bad;
						}
					}/* end of if(isap) */
                } /* end of if(icm_is_devap() */
			} /* end of if(!flag) */
        } /* end of if(icm_is_vap_radiochild()) */
    } /* end of for loop*/

	picm->numdevs = numdevs;
	if(picm->numdevs > 0) {
        picm->phy_spec = icm_get_radio_phy_spec(picm->dev_ifname);
        picm->band = icm_get_radio_band(picm->dev_ifname);
        picm->def_channel = icm_get_radio_default_channel(picm->dev_ifname);
        picm->channel_width = icm_get_radio_channel_width(picm->dev_ifname);
        if (strlcpy(picm->radio_ifname, radio_ifname, IFNAMSIZ) >= IFNAMSIZ) {
            fprintf(stderr, "radio_ifname too long: %s\n", radio_ifname);
            goto bad;
        }
        memcpy(picm->radio_addr, radio_addr, MAX_ADDR_LEN);
   }

    status = SUCCESS;

bad:
    icm_sys_ifnames_deinit(&vap_listing);

    return status;
}

/*
 * Function     : icm_configure_radio_iface
 * Description  : it dynamically configures the radio interface
 *					if interface goes up/down.
 * Input params : pointer pointing to ICM_DEV_INFO_T
 * Return       : Success
 *				  Failure
 *
 */
int icm_configure_radio_iface(ICM_DEV_INFO_T* pdev)
{
    int status = SUCCESS;
    int i = 0;
    ICM_CONFIG_T* conf = &pdev->conf;
    ICM_INFO_T* picm = NULL;
    sys_ifnames radio_listing;

    /* auto detect radio interface */
    if (icm_build_radio_listing(&radio_listing) != SUCCESS) {
        err("Could not create radio listing");
		status = FAILURE;
		goto out;
    }

    /* update the no. of radio devices */
    conf->num_radios = radio_listing.curr_size;
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN, "No. of radio found %d\n", conf->num_radios);

    for (i = 0; i < conf->num_radios; i++) {
        picm = &pdev->icm[i];

        if (picm == NULL) {
            err("Could not get icm info");
			status = FAILURE;
		}

        if (icm_init_radio_iface(picm, radio_listing.ifnames[i]) != SUCCESS) {
            err("Could not initilize the radio interface");
	    	status = FAILURE;
        }
	}

out:
	    icm_sys_ifnames_deinit(&radio_listing);

        return status;

}

/*
 * Function     : icm_set_ext_acs_inprogress
 * Description  : Helper function to indicate that external ACS is in progress,
 *                on a given interface.
 * Input params : pointer to pdev, pointer to icm
 * Return       : SUCCESS/FAILURE
 */
int icm_set_ext_acs_inprogress(ICM_DEV_INFO_T *pdev, ICM_INFO_T *picm)
{
    int ret = 0;

    ret = set_vap_priv_int_param(pdev,
                                 picm->dev_ifname,
                                 IEEE80211_PARAM_EXT_ACS_IN_PROGRESS,
                                 1);
    if (ret < 0) {
       fprintf(stderr,
               "%-8.16s  Could not set external ACS in progress indicator on "
               "interface\n\n",
               picm->dev_ifname);
       return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_clear_ext_acs_inprogress
 * Description  : Helper function to clear indication of external ACS being in
 *                progress, on a given interface.
 * Input params : pointer to pdev, pointer to icm
 * Return       : SUCCESS/FAILURE
 */
int icm_clear_ext_acs_inprogress(ICM_DEV_INFO_T *pdev, ICM_INFO_T *picm)
{
    int ret = 0;
    ret = set_vap_priv_int_param(pdev,
                                 picm->dev_ifname,
                                 IEEE80211_PARAM_EXT_ACS_IN_PROGRESS,
                                 0);
    if (ret < 0) {
       fprintf(stderr,
               "%-8.16s  Could not clear external ACS in progress indicator on "
               "interface\n\n",
               picm->dev_ifname);
       return FAILURE;
    }

    return SUCCESS;
}
