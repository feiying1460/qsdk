/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include "includes.h"
#include "common.h"
#include "linux_ioctl.h"
#include "wpa_ctrl.h"
#include "ieee802_11_defs.h"
#include "linux_wext.h"
#include "eloop.h"
#include "netlink.h"
#include "priv_netlink.h"
#include <fcntl.h>
#include <errno.h>

#include "iface_mgr_api.h"

#define _BYTE_ORDER _BIG_ENDIAN
#include "ieee80211_external.h"

#define MAX_RADIOS_CNT 3
#define MAX_RADIOS_CNT_FAST_LANE 2

#define CONN_FAIL_COUNT    10

#define WPA_S_MSG_ADDR_OFF      3

#define MAX_AP_VAPS_CNT 16

#define MAX_PLC_IFACE 1

#define IFACEMGR_MAX_CMD_LEN 128

#define HYD_BACK_HAUL_IFACE_PLC_UP        0x01
#define HYD_BACK_HAUL_IFACE_PLC_DOWN      0x02


struct ifacemgr_event_message {
    unsigned int cmd;
    unsigned int len;
    unsigned char data[1];
} __attribute__ ((packed));


/* Socket for HYD and IFACE MGR communication */
#define HYD_IFACE_MGR_SOCKET_CLIENT    "/var/run/hyd_iface_mgr_socket_client"

struct ifacemgr_ctrl {
    int sock;
    struct sockaddr_un local;
    struct sockaddr_un dest;
};

struct sta_vap {
    char ifname[IFNAMSIZ];
    char wifi_ifname[IFNAMSIZ];
    struct ifacemgr_ctrl *ifacemgr_stavap_conn;
    u_int8_t sta_vap_up;
    char *wpa_conf_file;
    u_int8_t conn_fail_count;
    struct group_data *gptr;
};

struct plc_iface {
    char ifname[IFNAMSIZ];
    u_int8_t plc_iface_up;
    struct group_data *gptr;
    int hyd_sock;
};

struct group_data {
    u_int8_t num_sta_vaps;
    u_int8_t num_sta_vaps_up;
    u_int8_t num_ap_vaps;
    u_int8_t is_primary_group;
    u_int8_t group_idx;
    struct sta_vap *stavap[MAX_RADIOS_CNT];
    char *ap_vap[MAX_AP_VAPS_CNT];
    struct plc_iface *plciface[MAX_PLC_IFACE];
    struct iface_daemon *iptr;
    u_int8_t num_plc_iface;
    u_int8_t num_plc_iface_up;
};

struct iface_daemon {
    u_int8_t mode;
    int8_t primary_group_idx;
    u_int16_t timeout;
    int ioctl_sock;
    struct wpa_ctrl *global;
    struct group_data group[MAX_RADIOS_CNT];
    char wifi_iface[IFNAMSIZ];
};

#define IFACE_MODE_GLOBALWDS 1
#define IFACE_MODE_FASTLANE 2
static int ping_interval = 5;

static const char *wpa_s_ctrl_iface_dir = "/var/run/wpa_supplicant";

ifacemgr_hdl_t *
ifacemgr_load_conf_file(const char *conf_file, int *num_sta_vaps, int *num_plc_ifaces)
{
    FILE *f;
    char buf[256], *pos, *start, *iface, *group, *iface_type;
    int line = 0, i = 0;
    int group_id = 0;

    struct iface_daemon *iptr;
    struct sta_vap *stavap = NULL;
    struct plc_iface *plciface = NULL;
    char *ap_ifname = NULL;
    int stavap_configured = 0;
    int plciface_configured = 0;

    iptr = os_zalloc(sizeof(*iptr));
    if (!iptr)
	return NULL;

    f = fopen(conf_file, "r");
    if (f == NULL) {
	ifacemgr_printf("Cant open oma conf file(%s)", conf_file);
	return NULL;
    }

    while ((fgets(buf, sizeof(buf), f))) {
	line ++;
	if ((buf[0] == '#') || (buf[0] == ' '))
	    continue;
	pos = buf;
	while (*pos != '\0') {
	    if (*pos == '=') {
		pos ++;
		break;
	    }
	    pos ++;
	}
	while (*pos != '\0') {
	    if (*pos == ' ') {
		pos ++;
		continue;
	    } else {
		break;
	    }
	}
	start = pos;
	while (*pos != '\0') {
	    if (*pos == '\n') {
		*pos = '\0';
		break;
	    }
	    pos ++;
	}

	switch(buf[0])
	{
	    case 'M':
	    case 'm':
		iptr->mode = atoi(start);
		break;
	    case 'T':
	    case 't':
		iptr->timeout = atoi(start);
		break;
	    case 'R':
	    case 'r':
		strlcpy(iptr->wifi_iface, start, IFNAMSIZ);
                ifacemgr_printf("iptr->radio:%s",iptr->wifi_iface);
		break;
	    case 'G':
	    case 'g':
		group=start;
		while (*start != '\0') {
		    if (*start == ' ') {
			*start = '\0';
			group_id=atoi(group);
			start ++;
			break;
		    }
		    start ++;
		}
		if (group_id >=3) {
		    ifacemgr_printf("group_id(%d) should not be greater than or equal to 3",group_id);
		    break;
		}
		iface_type=start;
		while (*start != '\0') {
		    if (*start == '=') {
			start ++;
			break;
		    }
		    start ++;
		}
		while (*start != '\0') {
		    if (*start == ' ') {
			start ++;
			continue;
		    } else {
			break;
		    }
		}

		iface=start;
		ap_ifname = NULL;
		if ((iface_type[0] == 'A') || (iface_type[0] == 'a')) {
		    for (i = 0; i < MAX_AP_VAPS_CNT; i++) {
			if (iptr->group[group_id].ap_vap[i] == NULL) {
			    ap_ifname = os_strdup(iface);
			    iptr->group[group_id].ap_vap[i] = ap_ifname;
			    break;
			}
		    }
		    if (ap_ifname) {
			iptr->group[group_id].num_ap_vaps ++;
		    } else {
			ifacemgr_printf("line:%d Not able to add ap vap", line);
		    }

		    stavap = NULL;
		} else if ((iface_type[0] == 'S') || (iface_type[0] == 's')) {
		    for (i = 0; i < MAX_RADIOS_CNT; i++) {
			if (iptr->group[group_id].stavap[i] == NULL) {
			    stavap = (struct sta_vap *)os_malloc(sizeof(struct sta_vap));
			    iptr->group[group_id].stavap[i] = stavap;
			    break;
			}
		    }
		    if (stavap) {
			strlcpy(stavap->ifname, iface, IFNAMSIZ);
			iptr->group[group_id].num_sta_vaps ++;
			stavap_configured ++;
		    } else {
			ifacemgr_printf("line:%d Not able to add sta vap", line);
		    }
		} else if ((iface_type[0] == 'P') || (iface_type[0] == 'p')) {
		    for (i = 0; i < MAX_PLC_IFACE; i++) {
			if (iptr->group[group_id].plciface[i] == NULL) {
			    plciface = (struct plc_iface *)os_malloc(sizeof(struct plc_iface));
			    iptr->group[group_id].plciface[i] = plciface;
			    break;
			}
		    }
		    if (plciface) {
			strlcpy(plciface->ifname, iface, IFNAMSIZ);
			iptr->group[group_id].num_plc_iface ++;
			plciface_configured ++;
		    } else {
			ifacemgr_printf("line:%d Not able to add plc iface", line);
		    }

		} else {
		    ifacemgr_printf("line:%d unknown interface", line);
		}
		break;
	    default:
		ifacemgr_printf("wrong input");
		break;
	}
    }
    *num_sta_vaps = stavap_configured;
    *num_plc_ifaces = plciface_configured;
    if (stavap_configured == 0) {
	ifacemgr_printf("No STA VAPs are configured");
    }
    if (plciface_configured == 0) {
	ifacemgr_printf("No PLC ifaces are configured");
    }
    ifacemgr_printf("num_sta_vaps:%d num_plc_ifaces:%d",*num_sta_vaps,*num_plc_ifaces);

    close((int)f);

    return (void *) iptr;
}

int
ifacemgr_conn_to_global_wpa_s(const char *global_supp, ifacemgr_hdl_t *ifacemgr_handle)
{

    struct iface_daemon *iptr = (struct iface_daemon *)ifacemgr_handle;
    char *realname = (void *)global_supp;
    if (!realname)
	return 0;

    iptr->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (iptr->ioctl_sock < 0) {
	ifacemgr_printf("socket[PF_INET,SOCK_DGRAM]");
	return 0;
    }

    iptr->global = wpa_ctrl_open(realname);
    if (!iptr->global) {
	close(iptr->ioctl_sock);
	ifacemgr_printf("Fail to connect global wpa_s");
	return 0;
    }

    ifacemgr_printf("connected to global wpa_s");
    return 1;

}


static void
ifacemgr_bringdown_apvaps(struct group_data *gptr)
{
    int i=0;
    char cmd[IFACEMGR_MAX_CMD_LEN] = {0};
    size_t res;

    for (i=0;i<gptr->num_ap_vaps;i++) {
	if (gptr->ap_vap[i]) {
            ifacemgr_printf("Bringing down AP VAPs(%s)",gptr->ap_vap[i]);
	    res = snprintf(cmd, sizeof(cmd), "ifconfig %s down", gptr->ap_vap[i]);
	    if (res < 0 || res >= sizeof(cmd))
		return;

	    cmd[sizeof(cmd) - 1] = '\0';
	    system(cmd);
	} else {
	    ifacemgr_printf("AP VAP iface not found");
	}
    }
}

static void
ifacemgr_bringup_apvaps(struct group_data *gptr)
{
    int i=0;
    char cmd[IFACEMGR_MAX_CMD_LEN] = {0};
    size_t res;

    for (i=0;i<gptr->num_ap_vaps;i++) {
	if (gptr->ap_vap[i]) {
            ifacemgr_printf("Bringing up AP VAPs(%s)",gptr->ap_vap[i]);
	    res = snprintf(cmd, sizeof(cmd), "ifconfig %s up", gptr->ap_vap[i]);
	    if (res < 0 || res >= sizeof(cmd))
		return;

	    cmd[sizeof(cmd) - 1] = '\0';
	    system(cmd);
	} else {
	    ifacemgr_printf("AP VAP iface not found");
	}
    }
}

static void
ifacemgr_bring_updown_stavaps(struct group_data *gptr,int op)
{
    int i=0;
    char cmd[IFACEMGR_MAX_CMD_LEN] = {0};
    size_t res;

    for (i=0;i<gptr->num_sta_vaps;i++) {
        if (gptr->stavap[i]) {
            ifacemgr_printf("Bringing %s STA VAPs(%s)",op ? "up" : "down",gptr->stavap[i]->ifname);
            res = snprintf(cmd, sizeof(cmd), "ifconfig %s %s", gptr->stavap[i]->ifname,op ? "up" : "down");
            if (res < 0 || res >= sizeof(cmd))
                return;

            cmd[sizeof(cmd) - 1] = '\0';
            system(cmd);
        } else {
            ifacemgr_printf("STA VAP iface not found");
        }
    }
}
#define ifacemgr_bringdown_stavaps(gptr) ifacemgr_bring_updown_stavaps(gptr,0)

#define ifacemgr_bringup_stavaps(gptr) ifacemgr_bring_updown_stavaps(gptr,1)

static void
ifacemgr_disconn_timer(void *eloop_ctx, void *timeout_ctx)
{
    struct group_data *gptr = (struct group_data *)eloop_ctx;

    ifacemgr_bringdown_apvaps(gptr);
    eloop_cancel_timeout(ifacemgr_disconn_timer, gptr, NULL);
    return;
}

static void
ifacemgr_primarygrp_conn_timer(void *eloop_ctx, void *timeout_ctx)
{
    struct group_data *gptr = (struct group_data *)eloop_ctx;

    ifacemgr_bringdown_stavaps(gptr);
    return;
}

static void
ifacemgr_backhaul_up_down_event_process(struct group_data *gptr, int event_flag)
{
    struct iface_daemon *iptr = gptr->iptr;
    struct ifreq ifr;
    struct extended_ioctl_wrapper extended_cmd;
    int ret;

    if (((gptr->num_sta_vaps_up + gptr->num_plc_iface_up) ==0) && !event_flag) {
	/* Get Disconnection timeout*/
	os_memset(&ifr, 0, sizeof(ifr));
	os_memcpy(ifr.ifr_name, iptr->wifi_iface, IFNAMSIZ);
	extended_cmd.cmd = EXTENDED_SUBIOCTL_GET_DISCONNECTION_TIMEOUT;
	ifr.ifr_data = (caddr_t) &extended_cmd;
	extended_cmd.data = (caddr_t)&iptr->timeout;
	if ((ret = ioctl(iptr->ioctl_sock, SIOCGATHEXTENDED, &ifr)) != 0) {
	    ifacemgr_printf("ret=%d ioctl SIOCGATHEXTENDED get timeout err", ret);
	} else {
	    ifacemgr_printf("iptr->timeout: %d \n", iptr->timeout);
	}
	eloop_register_timeout(iptr->timeout, 0, ifacemgr_disconn_timer, gptr, NULL);
    }

    if (((gptr->num_sta_vaps_up + gptr->num_plc_iface_up) ==1) && event_flag) {
	eloop_cancel_timeout(ifacemgr_disconn_timer, gptr, NULL);
	ifacemgr_bringup_apvaps(gptr);
    }
    return;
}


void
ifacemgr_wpa_s_ctrl_iface_process(struct sta_vap *stavap, char *msg)
{
    struct group_data *gptr = stavap->gptr;
    struct iface_daemon *iptr = gptr->iptr;

    if (os_strncmp(msg + WPA_S_MSG_ADDR_OFF, "CTRL-EVENT-DISCONNECTED ", 24) == 0) {
        if (!stavap->sta_vap_up) {
            return;
        }
        ifacemgr_printf("CTRL-EVENT-DISCONNECTED(%s)",stavap->ifname);
        stavap->sta_vap_up = 0;
        gptr->num_sta_vaps_up --;

        if (gptr->num_sta_vaps_up == 0) {

            if(IFACE_MODE_FASTLANE == (iptr->mode)) {
                /*Bring Up the STA VAP of alternate group*/
                int tmp_grp_idx = (gptr->is_primary_group) ? (!iptr->primary_group_idx) : (iptr->primary_group_idx);
                struct group_data *tmp_gptr = &(iptr->group[tmp_grp_idx]);
                ifacemgr_bringup_stavaps(tmp_gptr);
	    } else {
                ifacemgr_backhaul_up_down_event_process(gptr, 0);
            }
        }
    } else if (os_strncmp(msg + WPA_S_MSG_ADDR_OFF, "CTRL-EVENT-CONNECTED ", 21) == 0) {
        if (stavap->sta_vap_up) {
            return;
        }
        stavap->sta_vap_up = 1;
        gptr->num_sta_vaps_up ++;
        ifacemgr_printf("CTRL-EVENT-CONNECTED(%s)",stavap->ifname);
        if (gptr->num_sta_vaps_up == 1) {
            if(IFACE_MODE_FASTLANE == (iptr->mode)) {
                if(gptr->is_primary_group) {
                    struct group_data *secondary_gptr = &(iptr->group[!iptr->primary_group_idx]);
                    eloop_cancel_timeout(ifacemgr_primarygrp_conn_timer, gptr, NULL);
                    ifacemgr_bringup_apvaps(gptr);
                    /*Bring down secondary group if up*/
                    ifacemgr_bringdown_apvaps(secondary_gptr);
                    ifacemgr_bringdown_stavaps(secondary_gptr);
                } else {
                    struct group_data *primary_gptr = &(iptr->group[iptr->primary_group_idx]);
                    ifacemgr_bringup_apvaps(gptr);
                    ifacemgr_bringdown_apvaps(primary_gptr);
                    eloop_register_timeout(iptr->timeout, 0, ifacemgr_primarygrp_conn_timer, primary_gptr, NULL);
                }
            } else {
                ifacemgr_backhaul_up_down_event_process(gptr, 1);
            }
        }
        if ((gptr->num_sta_vaps_up == 2) && (IFACE_MODE_FASTLANE == (iptr->mode))) {
            if(gptr->is_primary_group) {
                struct group_data *secondary_gptr = &(iptr->group[!iptr->primary_group_idx]);
                eloop_cancel_timeout(ifacemgr_primarygrp_conn_timer, gptr, NULL);
                ifacemgr_bringup_apvaps(gptr);
                /*Bring down secondary group if up*/
                ifacemgr_bringdown_apvaps(secondary_gptr);
                ifacemgr_bringdown_stavaps(secondary_gptr);
            }
        }
    } else {
       //             ifacemgr_printf("Unknown msg(%s)", msg + WPA_S_MSG_ADDR_OFF);
    }

}

void
ifacemgr_wpa_s_ctrl_iface_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
    struct sta_vap *stavap = (struct sta_vap *)eloop_ctx;
    char msg[256];
    int res;
    struct sockaddr_un from;
    socklen_t fromlen = sizeof(from);

    res = recvfrom(sock, msg, sizeof(msg) - 1, 0, (struct sockaddr *) &from, &fromlen);
    if (res < 0) {
        ifacemgr_printf("recvfrom err");
        return;
    }
    msg[res] = '\0';

    ifacemgr_wpa_s_ctrl_iface_process(stavap, msg);
}


struct ifacemgr_ctrl *
ifacemgr_conn_to_sta_wpa_s(char *ifname)
{
    struct wpa_ctrl *priv = NULL;
    char *cfile;
    int flen;

    if (ifname == NULL)  {
        ifacemgr_printf("ERROR:ifname is Null in %s\n", __func__);
        return NULL;
    }

    flen = strlen(wpa_s_ctrl_iface_dir) + (2*strlen(ifname)) + 3;
    cfile = malloc(flen);
    if (cfile == NULL)
        return NULL;

    snprintf(cfile, flen, "%s-%s/%s", wpa_s_ctrl_iface_dir, ifname, ifname);
    priv = wpa_ctrl_open(cfile);
    if (!priv) {
        ifacemgr_printf("cfile %s connection to sta vap failed\n", cfile);
    }
    free(cfile);
    return (struct ifacemgr_ctrl *)priv;
}


static int
ifacemgr_get_80211param(struct iface_daemon *iptr, char *ifname, int op, int *data)
{
    struct iwreq iwr;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

    iwr.u.mode = op;

    if (ioctl(iptr->ioctl_sock, IEEE80211_IOCTL_GETPARAM, &iwr) < 0) {
        ifacemgr_printf("ioctl IEEE80211_IOCTL_GETPARAM err, ioctl(%d) op(%d)",
                IEEE80211_IOCTL_GETPARAM, op);
        return -1;
    }

    *data = iwr.u.mode;
    return 0;
}

void
ifacemgr_ifname_to_parent_ifname(struct iface_daemon *iptr, char *child, char *parent)
{
    struct ifreq ifr;
    int parent_index=0;

    ifacemgr_get_80211param(iptr, child, IEEE80211_PARAM_PARENT_IFINDEX, &parent_index);

    os_memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = parent_index;
    if (ioctl(iptr->ioctl_sock, SIOCGIFNAME, &ifr) != 0) {
        ifacemgr_printf("ioctl SIOCGIFNAME err");
        return;
    }

    os_memcpy(parent, ifr.ifr_name, IFNAMSIZ);
}

void ifacemgr_free_ifacemgr_handle(ifacemgr_hdl_t *ifacemgr_handle)
{
    struct iface_daemon *iptr = (struct iface_daemon *)ifacemgr_handle;
    struct group_data *gptr = NULL;
    int i = 0, j = 0;
    struct sta_vap *stavap = NULL;
    struct plc_iface *plciface = NULL;
    for (i = 0; i < MAX_RADIOS_CNT; i++) {
        gptr =  &(iptr->group[i]);
        gptr->iptr = iptr;
        for (j = 0; j < gptr->num_sta_vaps; j++) {

            if(gptr->stavap[j] == NULL) {
                continue;
            }
            stavap = gptr->stavap[j];
            os_free(stavap->wpa_conf_file);
            os_free(stavap);
        }
      for (j = 0; j < gptr->num_plc_iface; j++) {

            if(gptr->plciface[j] == NULL) {
                continue;
            }
            plciface = gptr->plciface[j];
            eloop_unregister_read_sock(plciface->hyd_sock);
            close(plciface->hyd_sock);
            os_free(plciface);
        }

        for (j = 0; j < gptr->num_ap_vaps; j++) {
            if(gptr->ap_vap[j]) {
                os_free(gptr->ap_vap[j]);
            }
        }

    }
    os_free(iptr);
}

int ifacemgr_stavap_conn_to_wpa_supplicant(struct sta_vap *stavap)
{

    stavap->ifacemgr_stavap_conn = ifacemgr_conn_to_sta_wpa_s(stavap->ifname);
    if(stavap->ifacemgr_stavap_conn) {
        if (wpa_ctrl_attach((struct wpa_ctrl *)stavap->ifacemgr_stavap_conn) != 0) {
            if(!(stavap->conn_fail_count % CONN_FAIL_COUNT)){
                ifacemgr_printf("Failed to attach to MPSTA wpa_s(%s)", stavap->ifname);
            }
            stavap->conn_fail_count++;
            wpa_ctrl_close((struct wpa_ctrl *)stavap->ifacemgr_stavap_conn);
            stavap->ifacemgr_stavap_conn = NULL;
            return 0;
        }
        eloop_register_read_sock(stavap->ifacemgr_stavap_conn->sock, ifacemgr_wpa_s_ctrl_iface_receive, stavap, NULL);
    } else {
        if(!(stavap->conn_fail_count % CONN_FAIL_COUNT)){
            ifacemgr_printf("STA wpa_s(%s) not exists", stavap->ifname);
        }
        stavap->conn_fail_count++;
        return 0;
    }
    return 1;
}

void
ifacemgr_display_updated_config(ifacemgr_hdl_t *ifacemgr_handle)
{
    struct iface_daemon *iptr = (struct iface_daemon *)ifacemgr_handle;
    struct group_data *gptr = NULL;
    int i = 0, j = 0;
    struct sta_vap *stavap = NULL;
    struct plc_iface *plciface = NULL;

    ifacemgr_printf("Mode:%d timeout:%d",iptr->mode,iptr->timeout);
    for (i = 0; i < MAX_RADIOS_CNT; i++) {
        gptr =  &(iptr->group[i]);
        if (gptr->num_sta_vaps || gptr->num_ap_vaps) {
            printf("\nGroup ID: %d\n", i);
        }
        if (gptr->num_sta_vaps) {
            printf("STA VAP list: ");
        }
        for (j = 0; j < gptr->num_sta_vaps; j++) {

            if(gptr->stavap[j] == NULL) {
                continue;
            }
            stavap = gptr->stavap[j];
            printf("%s\t", stavap->ifname);
        }
        if (gptr->num_ap_vaps) {
            printf("\nAP VAP list: ");
        }
        for (j = 0; j < gptr->num_ap_vaps; j++) {
            if(gptr->ap_vap[j]) {
                printf("%s\t", gptr->ap_vap[j]);
            }
        }
        if (gptr->num_plc_iface) {
            printf("PLC iface list: ");
        }
        for (j = 0; j < gptr->num_plc_iface; j++) {

            if(gptr->plciface[j] == NULL) {
                continue;
            }
            plciface = gptr->plciface[j];
            printf("%s\t", plciface->ifname);
        }

    }
    printf("\n");
}

void
ifacemgr_status_inform_to_driver(ifacemgr_hdl_t *ifacemgr_handle, u_int8_t iface_mgr_up)
{
    struct iface_daemon *iptr = (struct iface_daemon *)ifacemgr_handle;
    struct ifreq ifr;
    struct extended_ioctl_wrapper extended_cmd;
    int ret = 0;

    /*
     * Inform driver about status of interface manager
     * only if globalwds option is set.
     */
    if (IFACE_MODE_GLOBALWDS == (iptr->mode)) {
        os_memset(&ifr, 0, sizeof(ifr));
        os_memcpy(ifr.ifr_name, iptr->wifi_iface, IFNAMSIZ);
        extended_cmd.cmd = EXTENDED_SUBIOCTL_IFACE_MGR_STATUS;
        ifr.ifr_data = (caddr_t) &extended_cmd;
        extended_cmd.data = (caddr_t)&iface_mgr_up;
        if ((ret = ioctl(iptr->ioctl_sock, SIOCGATHEXTENDED, &ifr)) != 0) {
            ifacemgr_printf("ret=%d ioctl SIOCGATHEXTENDED iface_mgr up err", ret);
        } else {
            ifacemgr_printf("iface mgr status:%d\n",iface_mgr_up);
        }
    }
}

static int ifacemgr_stavap_config(struct sta_vap *stavap){
    struct group_data *gptr = stavap->gptr;
    struct iface_daemon *iptr = gptr->iptr;
    struct ifreq ifr;
    struct extended_ioctl_wrapper extended_cmd;
    int  ret;

    /*find parent interface*/
    ifacemgr_ifname_to_parent_ifname(iptr, stavap->ifname, stavap->wifi_ifname);

    if((IFACE_MODE_FASTLANE == (iptr->mode)) && (iptr->primary_group_idx < 0)) {
        int  is_preferredUplink = 0;
        /*
         * If interface manager is operating in Mode 2, then get the preferredUplink information
         */

        os_memset(&ifr, 0, sizeof(ifr));
        os_memcpy(ifr.ifr_name, stavap->wifi_ifname, IFNAMSIZ);
        extended_cmd.cmd = EXTENDED_SUBIOCTL_GET_PREF_UPLINK;
        ifr.ifr_data = (caddr_t) &extended_cmd;
        extended_cmd.data = (caddr_t)&is_preferredUplink;

        if ((ret = ioctl(iptr->ioctl_sock, SIOCGATHEXTENDED, &ifr)) != 0) {
            ifacemgr_printf("ret=%d ioctl SIOCGATHEXTENDED get_pref_Uplink err", ret);
        } else {
            ifacemgr_printf("Preferred Uplink status:%d",is_preferredUplink);
        }

        if(is_preferredUplink) {
            /*Preferred Uplink found ;so no need to loop through all the radios*/
            iptr->primary_group_idx = gptr->group_idx;
            gptr->is_primary_group = 1;
        }
    }

    /* Get stavap connection status*/
    os_memset(&ifr, 0, sizeof(ifr));
    os_memcpy(ifr.ifr_name, stavap->wifi_ifname, IFNAMSIZ);
    extended_cmd.cmd = EXTENDED_SUBIOCTL_GET_STAVAP_CONNECTION;
    ifr.ifr_data = (caddr_t) &extended_cmd;
    extended_cmd.data = (caddr_t)&stavap->sta_vap_up;
    if ((ret = ioctl(iptr->ioctl_sock, SIOCGATHEXTENDED, &ifr)) != 0) {
        ifacemgr_printf("ret=%d ioctl SIOCGATHEXTENDED getsta_vap_up err", ret);
    } else {
        ifacemgr_printf("initial stavap(%s) connection: %d", stavap->ifname,stavap->sta_vap_up);
    }
    if (stavap->sta_vap_up) {
        gptr->num_sta_vaps_up ++;
    }

    if(IFACE_MODE_FASTLANE != (iptr->mode)) {
        if (gptr->num_sta_vaps_up) {
            ifacemgr_bringup_apvaps(gptr);
        } else {
            ifacemgr_bringdown_apvaps(gptr);
        }
    }

    if((IFACE_MODE_FASTLANE == (iptr->mode)) && (iptr->primary_group_idx >= 0)) {
        struct group_data *primary_gptr = NULL;
        struct group_data *secondary_gptr = NULL;

        primary_gptr = &(iptr->group[iptr->primary_group_idx]);
        secondary_gptr = &(iptr->group[!iptr->primary_group_idx]);
        /*
         * Check if the primary group STA VAP is connected.
         * If connected, then bring down the secondary group.
         */
        if(primary_gptr->num_sta_vaps_up) {
            ifacemgr_bringup_apvaps(primary_gptr);
            ifacemgr_bringdown_apvaps(secondary_gptr);
            ifacemgr_bringdown_stavaps(secondary_gptr);
        } else if(secondary_gptr->num_sta_vaps_up) {
            /*
             * Since a secondary group STA VAP is connected,
             * bring up the AP VAPs of secondary group and
             * register a timer call back handler for time out.
             */
            ifacemgr_bringup_apvaps(secondary_gptr);
            ifacemgr_bringdown_apvaps(primary_gptr);
            eloop_register_timeout(iptr->timeout, 0, ifacemgr_primarygrp_conn_timer, primary_gptr, NULL);
        }
    }

    return 0;
}

static void ifacemgr_wpa_cli_ping(void *eloop_ctx, void *timeout_ctx)
{
    struct sta_vap *stavap = (struct sta_vap *)eloop_ctx;
    struct group_data *gptr = NULL;

    if(NULL == stavap){
        ifacemgr_printf("failed to make sta vap conn with wpa supplicant\n");
        return;
    }

    gptr = stavap->gptr;

    if (stavap->ifacemgr_stavap_conn) {
        int res;
        char buf[4096];
        size_t len;
        len = sizeof(buf) - 1;
        res = wpa_ctrl_request((struct wpa_ctrl *)stavap->ifacemgr_stavap_conn,
                                "PING", strlen("PING"), buf, &len,NULL);

        if (res < 0) {
            ifacemgr_printf("Connection to wpa_supplicant lost - trying to reconnect\n");
            eloop_unregister_read_sock(stavap->ifacemgr_stavap_conn->sock);
            wpa_ctrl_detach((struct wpa_ctrl *)stavap->ifacemgr_stavap_conn);
            wpa_ctrl_close((struct wpa_ctrl *)stavap->ifacemgr_stavap_conn);
            stavap->ifacemgr_stavap_conn = NULL;
        }
    }

    if(!stavap->ifacemgr_stavap_conn) {
        if (stavap->sta_vap_up)
            gptr->num_sta_vaps_up --;
        stavap->sta_vap_up = 0;
        if(ifacemgr_stavap_conn_to_wpa_supplicant(stavap)){
            ifacemgr_stavap_config(stavap);
        }
    }
    eloop_register_timeout(ping_interval, 0, ifacemgr_wpa_cli_ping, stavap, NULL);
}

static void ifacemgr_try_connection(void *eloop_ctx, void *timeout_ctx)
{
    struct sta_vap *stavap = (struct sta_vap *)eloop_ctx;
    int ret;

    if(NULL == stavap){
        ifacemgr_printf("failed to make sta vap conn with wpa supplicant\n");
        return;
    }

    ret = ifacemgr_stavap_conn_to_wpa_supplicant(stavap);
    if (!ret) {
        ifacemgr_printf("failed to make sta vap conn with wpa supplicant\n");
        eloop_register_timeout(1, 0, ifacemgr_try_connection, stavap, NULL);
    }else {
        ifacemgr_stavap_config(stavap);
        eloop_register_timeout(ping_interval, 0, ifacemgr_wpa_cli_ping, stavap, NULL);
    }
}

int
ifacemgr_update_ifacemgr_handle_config(ifacemgr_hdl_t *ifacemgr_handle)
{
    struct iface_daemon *iptr = (struct iface_daemon *)ifacemgr_handle;
    struct group_data *gptr = NULL;
    int i = 0, j = 0;
    struct sta_vap *stavap = NULL;
    char *wpa_s_conf_file = "/var/run/wpa_supplicant";
    char *cfile;
    int flen;
    int  max_radio_cnt = (IFACE_MODE_FASTLANE != (iptr->mode)) ? MAX_RADIOS_CNT : MAX_RADIOS_CNT_FAST_LANE;

    //set primary to -1 for error checking
    iptr->primary_group_idx = -1;

    for (i = 0; i < max_radio_cnt; i++) {
        gptr =  &(iptr->group[i]);
        gptr->iptr = iptr;
        gptr->group_idx = i;
        for (j = 0; j < gptr->num_sta_vaps; j++) {

            if(gptr->stavap[j] == NULL) {
                ifacemgr_printf("Failed to connect to MPSTA wpa_s - iptr->group[0].sta_vap[0] == NULL");
                continue;
            }
            stavap = gptr->stavap[j];
            stavap->gptr = gptr;
            flen = strlen(wpa_s_conf_file) + (strlen(stavap->ifname)) + 7;
            cfile = os_malloc(flen);
            if (cfile == NULL)
            {
                ifacemgr_printf("ERROR:malloc failed\n");
                return 0;
            }

            snprintf(cfile, flen, "%s-%s.conf", wpa_s_conf_file, stavap->ifname);

            stavap->wpa_conf_file = os_strdup(cfile);
            os_free(cfile);
            eloop_register_timeout(0, 0, ifacemgr_try_connection, stavap, NULL);
        }
    }

    return 1;
}

static
void ifacemgr_hyd_event_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
    char msg[256];
    int res;
    struct sockaddr_un from;
    socklen_t fromlen = sizeof(from);
    struct ifacemgr_event_message *message;
    struct plc_iface *plciface = (struct plc_iface *)eloop_ctx;
    struct group_data *gptr = plciface->gptr;

    res = recvfrom(sock, msg, sizeof(msg) - 1, MSG_DONTWAIT, (struct sockaddr *) &from, &fromlen);
    if (res < 0) {
	ifacemgr_printf("recvfrom Err no=%d", errno);
	return;
    }
    msg[res] = '\0';

    message = (struct ifacemgr_event_message *)msg;

    switch (message->cmd) {
	case HYD_BACK_HAUL_IFACE_PLC_UP:
            if (plciface->plc_iface_up == 1) {
                return;
            }
	    plciface->plc_iface_up = 1;
	    gptr->num_plc_iface_up++;
	    ifacemgr_printf("HYD_BACK_HAUL_IFACE_PLC_UP event received, gptr->num_plc_iface_up:%d", gptr->num_plc_iface_up);
	    ifacemgr_backhaul_up_down_event_process(gptr, 1);
	    break;
	case HYD_BACK_HAUL_IFACE_PLC_DOWN:
            if (plciface->plc_iface_up == 0) {
                return;
            }
	    plciface->plc_iface_up = 0;
	    gptr->num_plc_iface_up--;
	    ifacemgr_printf("HYD_BACK_HAUL_IFACE_PLC_DOWN event received, gptr->num_plc_iface_up:%d", gptr->num_plc_iface_up);
	    ifacemgr_backhaul_up_down_event_process(gptr, 0);
	    break;
	default:
	    break;
    }
    return;
}

int
ifacemgr_create_hydsock(ifacemgr_hdl_t *ifacemgr_handle)
{
    struct iface_daemon *iptr = (struct iface_daemon *)ifacemgr_handle;
    struct group_data *gptr = NULL;
    int i = 0, j = 0;
    struct plc_iface *plciface = NULL;
    int  max_radio_cnt = MAX_RADIOS_CNT;
    int32_t sock;
    int32_t plcsock_len;
    struct sockaddr_un clientAddr = {
                AF_UNIX,
                HYD_IFACE_MGR_SOCKET_CLIENT
    };


    for (i = 0; i < max_radio_cnt; i++) {
	gptr =  &(iptr->group[i]);
	gptr->iptr = iptr;
	gptr->group_idx = i;
        gptr->num_plc_iface_up = 0;
	for (j = 0; j < gptr->num_plc_iface; j++) {

	    if(gptr->plciface[j] == NULL) {
		ifacemgr_printf("Failed to connect to hyd - iptr->group[0].plciface[0] == NULL");
		continue;
	    }
	    plciface = gptr->plciface[j];
	    plciface->gptr = gptr;
            plciface->plc_iface_up = 0;
	    if ((sock = socket (AF_UNIX, SOCK_DGRAM, 0)) == -1)
	    {
		ifacemgr_printf("%s:Socket() failed. Err no=%d", __func__, errno);
		goto err;
	    }
	    memset(&clientAddr, 0, sizeof(clientAddr));
	    clientAddr.sun_family = AF_UNIX;
	    strlcpy(clientAddr.sun_path, HYD_IFACE_MGR_SOCKET_CLIENT, sizeof(HYD_IFACE_MGR_SOCKET_CLIENT));
	    plcsock_len = strlen(HYD_IFACE_MGR_SOCKET_CLIENT);

	    clientAddr.sun_path[plcsock_len] = '\0';
	    unlink(clientAddr.sun_path);
	    if (bind (sock, (struct sockaddr *)(&clientAddr), sizeof (clientAddr)) == -1)
	    {
		ifacemgr_printf("%s:Bind() failed. Err no=%d", __func__, errno);
		close(sock);
		goto err;
	    }

	    /* Set nonblock. */
	    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK))
	    {
		ifacemgr_printf("%s failed to set fd NONBLOCK", __func__);
		goto err;
	    }

	    plciface->hyd_sock = sock;

	    if (eloop_register_read_sock(sock, ifacemgr_hyd_event_receive, plciface, NULL)) {
		ifacemgr_printf("%s failed to register callback func", __func__);
		close(sock);
		goto err;
	    }

	}
    }
    return 1;
err:
    return 0;
}
