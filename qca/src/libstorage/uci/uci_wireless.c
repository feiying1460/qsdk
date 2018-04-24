
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include "sys/stat.h"
#include <sys/socket.h>
#include <linux/wireless.h>
#include <fcntl.h>
#include "compat.h"

#ifndef _BYTE_ORDER
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _BYTE_ORDER _LITTLE_ENDIAN
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define _BYTE_ORDER _BIG_ENDIAN
#endif
#endif  // _BYTE_ORDER

#ifdef NOT_UMAC
#include "net80211/ieee80211.h"
#include "net80211/ieee80211_crypto.h"
#include "net80211/ieee80211_ioctl.h"
#else
#include "ieee80211_external.h"
#endif

#include "uci_core.h"
#include "package.h"

#define IEEE80211_MAX_HTMODE_LEN 30 // maximum HT mode length used in driver

enum BEACONTYPE {
    BEACONTYPE_eNone = 1,
    BEACONTYPE_eBasic = 2,
    BEACONTYPE_eWPA = 3,
    BEACONTYPE_e11i = 4,
    BEACONTYPE_eWPAand11i = 7,
};

enum BASICENCRYPTIONMODES {
    BASICENCRYPTIONMODES_eNone = 1,
    BASICENCRYPTIONMODES_eWEPEncryption = 2,
};


enum BASICAUTHENTICATIONMODE {
    BASICAUTHENTICATIONMODE_eNone = 1,
    BASICAUTHENTICATIONMODE_eEAPAuthentication = 2,
    BASICAUTHENTICATIONMODE_eSharedAuthentication = 3,
    BASICAUTHENTICATIONMODE_eBoth = 4,
};


enum WPAENCRYPTIONMODES {
    WPAENCRYPTIONMODES_eTKIPEncryption = 1,
    WPAENCRYPTIONMODES_eAESEncryption = 2,
    WPAENCRYPTIONMODES_eTKIPandAESEncryption = 3,
};


enum WPAAUTHENTICATIONMODE {
    WPAAUTHENTICATIONMODE_ePSKAuthentication = 1,
    WPAAUTHENTICATIONMODE_eEAPAuthentication = 2,
};


enum IEEE11IENCRYPTIONMODES {
    IEEE11IENCRYPTIONMODES_eTKIPEncryption = 1,
    IEEE11IENCRYPTIONMODES_eAESEncryption = 2,
    IEEE11IENCRYPTIONMODES_eTKIPandAESEncryption = 3,
};


enum IEEE11IAUTHENTICATIONMODE {
    IEEE11IAUTHENTICATIONMODE_ePSKAuthentication = 1,
    IEEE11IAUTHENTICATIONMODE_eEAPAuthentication = 2,
    IEEE11IAUTHENTICATIONMODE_eEAPandPSKAuthentication = 3,
};


struct vapsec_s {
    int vapidx;
    char ifname[IFNAMSIZ+1];
    bool changed;
    bool opti_changed;
    struct vapsec_s *next;
    int bcn_type;
    int wep_encr;
    int wep_auth;
    int wpa_encr;
    int wpa_auth;
    int wpa2_encr;
    int wpa2_auth;
    int wep_keyidx;
    char *passphrase;
    char *psk;

    /*optimization for non-destructive operations on vaps*/
    char *channel;
    char *vapind;
    char *htmode;
    bool  isdown;
};

struct wireless_s{
    bool changed;
    struct vapsec_s *vsec;
};

struct wl_translate_option{
    char *optname;
    char *uciname;
    int (*opt2uci)(char *optval, char *ucival);   /*direct mapping*/
    int (*optparser)(struct uci_context *ctx, struct wireless_s *wl, int index, char *name, char *value); /*indirect mapping*/

};

static int do80211priv( const char *ifname, int op, void *data, size_t len)
{
    struct iwreq iwr;
    int sock;
    int ret;

    memset(&iwr, 0, sizeof(iwr));
    if (snprintf(iwr.ifr_name, IFNAMSIZ, "%s", ifname) < 0)
    {
        return -1;
    }

    if (len <= IFNAMSIZ) {
        /* inline argument if the size is small */
        memcpy(iwr.u.name, data, len);
    } else {
        /* Pointer to external buffer for long argument which cannot
         * be fit into inline buffer
         */
        iwr.u.data.pointer = data;
        iwr.u.data.length = len;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;

    ret = ioctl(sock, op, &iwr);
    close(sock);
    return ret;
}


static int wireless_vap_ifctl(const char *ifname, int up_down)
{
    struct ifreq ifr = {};
    int ret;
    int sock;

    if (snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname) < 0)
    {
        return -1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(sock < 0) {
        return -1;
    }

    ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    if (ret < 0)
    {
        close(sock);
        return ret;
    }

    if(up_down == 1) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    } else  {
        ifr.ifr_flags &= ~IFF_UP;
    }

    ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);

    return ret;
}

/*The mapping between vapidx and ifname is not stored in UCI configuration.
  It is generated dynamically by qcawifi.sh script. And it is stored in the
  state file of UCI. So here we need to get it by uci command.
*/
int wireless_get_ifname_by_vapidx(int vapidx, char *ifname)
{
    FILE *f;
    char path[256];
    char line[256];
    int len;
    int found = 0;
    char *endstr;

    snprintf(path, 256, "uci -q get -P /var/state wireless.@wifi-iface[%d].ifname", vapidx - 1);
    f =popen(path, "r");
    if(!f)
        return -1;

    memset(line, 0, sizeof(line));
    fgets(line, sizeof(line), f);
    endstr = strstr(line, "\n");
    if (endstr
        && endstr < line + sizeof(line))
        *endstr = '\0';

    len = strlen(line);
    if (len > 0)
    {
        snprintf(ifname, IFNAMSIZ, line);
        found = 1;
    }
    else
    {
        found = 0;
    }

    pclose(f);

    if (found == 1)
        return 0;
    else
        return -1;
}

int wireless_set_vapchannel(const char *ifname, int channel)
{
    int sock;
    int ret;
    struct iwreq iwr = { { { 0 } } };

    if (snprintf(iwr.ifr_name, IFNAMSIZ, "%s", ifname) < 0)
        return -1;

    iwr.u.freq.m = channel;
    iwr.u.freq.e = 0;
    iwr.u.freq.flags = IW_FREQ_FIXED;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;
    ret =ioctl(sock, SIOCSIWFREQ, &iwr);
    close(sock);

    return ret;
}

int wireless_set_vapind(const char *ifname, int vapind)
{
    int setvapind[2];

    setvapind[0] = IEEE80211_PARAM_VAP_ENHIND;
    setvapind[1] = vapind;

    if (do80211priv(ifname, IEEE80211_IOCTL_SETPARAM, setvapind, 2*sizeof(int)) < 0) {
        return -1;
    }
    return 0;
}

/**
 * @brief Configure the HT mode on given interface using "iwpriv mode" cmd
 *
 * @param [in] ifname  the given interface name
 * @param [in] htmode  the driver HT mode derived from "Standard" TLV
 */
static int wireless_set_vaphtmode(const char *ifname, const char *htmode)
{
    char cmd[30 + IFNAMSIZ + IEEE80211_MAX_HTMODE_LEN];
    if (snprintf(cmd, sizeof(cmd), "iwpriv %s mode %s", ifname, htmode) < sizeof(cmd)) {
        return system(cmd);
    }
    // Else not long enough, return error. It should not happen unless the driver
    // definition changes but the constants are not updated to reflect it.

    return -1;
}

static struct vapsec_s *wireless_get_vapsec(struct wireless_s *wl, int vapidx)
{
    struct vapsec_s *vsec = wl->vsec;
    while (vsec)
    {
        if (vsec->vapidx == vapidx)
            break;
        vsec = vsec->next;
    }

    if (!vsec)
    {
        vsec = malloc(sizeof(struct vapsec_s));
        if (!vsec)
        {
            return NULL;
        }

        memset(vsec, 0, sizeof(struct vapsec_s));
        vsec->vapidx = vapidx;
        vsec->next = wl->vsec;
        wl->vsec = vsec;
    }

    return vsec;
}

static int wireless_free_vapsec(struct wireless_s *wl)
{
    struct vapsec_s *vsec = wl->vsec;
    struct vapsec_s *tmp;

    while (vsec)
    {
        tmp =vsec;
        vsec = vsec->next;

        if(tmp->psk)
            free(tmp->psk);
        if (tmp->passphrase)
            free(tmp->passphrase);
        if (tmp->channel)
            free(tmp->channel);
        if (tmp->vapind)
            free(tmp->vapind);
        if (tmp->htmode)
            free(tmp->htmode);
        free(tmp);
    }

    wl->vsec = NULL;
    return 0;
}



static int opt_bool_revert(char *optval, char *ucival)
{
    if (!optval || !ucival)
        return -1;

    if (strcmp(optval, "0" ) == 0)
    {
        snprintf(ucival, UCI_MAX_STR_LEN, "1");
    }
    else if (strcmp(optval, "1" ) == 0)
    {
        snprintf(ucival, UCI_MAX_STR_LEN, "0");
    }
    else
    {
        return -1;
    }

    return 0;
}


static int opt_radidx_to_device(char *optval, char *ucival)
{
    if (!optval || !ucival)
        return -1;

    snprintf(ucival, UCI_MAX_STR_LEN, "wifi%d", atoi(optval) - 1);
    return 0;
}



static int opt_parse_bcntype(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "None") == 0)
    {
        vsec->bcn_type = BEACONTYPE_eNone;
    }
    else if (strcmp(value, "Basic") == 0)
    {
        vsec->bcn_type = BEACONTYPE_eBasic;
    }
    else if (strcmp(value, "WPA") == 0)
    {
        vsec->bcn_type = BEACONTYPE_eWPA;
    }
    else if (strcmp(value, "11i") == 0)
    {
        vsec->bcn_type = BEACONTYPE_e11i;
    }
    else if (strcmp(value, "WPAand11i") == 0)
    {
        vsec->bcn_type = BEACONTYPE_eWPAand11i;
    }
    else
    {
        return -1;
    }

    return 0;
}

static int opt_parse_wepencr(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "None") == 0)
    {
        vsec->wep_encr = BASICENCRYPTIONMODES_eNone;
    }
    else if (strcmp(value, "WEPEncryption") == 0)
    {
        vsec->wep_encr = BASICENCRYPTIONMODES_eWEPEncryption;
    }
    else
    {
        return -1;
    }

    return 0;
}


static int opt_parse_wepauth(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "None") == 0)
    {
        vsec->wep_auth = BASICAUTHENTICATIONMODE_eNone;
    }
    else if (strcmp(value, "EAPAuthentication") == 0)
    {
        vsec->wep_auth = BASICAUTHENTICATIONMODE_eEAPAuthentication;
    }
    else if (strcmp(value, "SharedAuthentication") == 0)
    {
        vsec->wep_auth = BASICAUTHENTICATIONMODE_eSharedAuthentication;
    }
    else if (strcmp(value, "Both") == 0)
    {
        vsec->wep_auth = BASICAUTHENTICATIONMODE_eBoth;
    }
    else
    {
        return -1;
    }

    return 0;
}


static int opt_parse_wpaencr(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "TKIPEncryption") == 0)
    {
        vsec->wpa_encr = WPAENCRYPTIONMODES_eTKIPEncryption;
    }
    else if (strcmp(value, "AESEncryption") == 0)
    {
        vsec->wpa_encr = WPAENCRYPTIONMODES_eAESEncryption;
    }
    else if (strcmp(value, "TKIPandAESEncryption") == 0)
    {
        vsec->wpa_encr = WPAENCRYPTIONMODES_eTKIPandAESEncryption;
    }
    else
    {
        return -1;
    }

    return 0;
}

static int opt_parse_wpaauth(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "PSKAuthentication") == 0)
    {
        vsec->wpa_auth = WPAAUTHENTICATIONMODE_ePSKAuthentication;
    }
    else if (strcmp(value, "EAPAuthentication") == 0)
    {
        vsec->wpa_auth = WPAAUTHENTICATIONMODE_eEAPAuthentication;
    }
    else
    {
        return -1;
    }

    return 0;
}

static int opt_parse_11iencr(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "TKIPEncryption") == 0)
    {
        vsec->wpa2_encr = IEEE11IENCRYPTIONMODES_eTKIPEncryption;
    }
    else if (strcmp(value, "AESEncryption") == 0)
    {
        vsec->wpa2_encr = IEEE11IENCRYPTIONMODES_eAESEncryption;
    }
    else if (strcmp(value, "TKIPandAESEncryption") == 0)
    {
        vsec->wpa2_encr = IEEE11IENCRYPTIONMODES_eTKIPandAESEncryption;
    }
    else
    {
        return -1;
    }

    return 0;
}

static int opt_parse_11iauth(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(value, "PSKAuthentication") == 0)
    {
        vsec->wpa2_auth = IEEE11IAUTHENTICATIONMODE_ePSKAuthentication;
    }
    else if (strcmp(value, "EAPAuthentication") == 0)
    {
        vsec->wpa2_auth = IEEE11IAUTHENTICATIONMODE_eEAPAuthentication;
    }
    else if (strcmp(value, "EAPandPSKAuthentication") == 0)
    {
        vsec->wpa2_auth = IEEE11IAUTHENTICATIONMODE_eEAPandPSKAuthentication;
    }
    else
    {
        return -1;
    }

    return 0;
}


static int opt_parse_psk(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec)
    {
        return -1;
    }

    if (strcmp(name, "KeyPassphrase") == 0 )
    {
        vsec->passphrase = strdup(value);
    }
    if (strcmp(name, "PreSharedKey.1.PreSharedKey") == 0 )
    {
        vsec->psk = strdup(value);
    }

    return 0;
}

static int opt_parse_wepkeyidx(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    struct vapsec_s *vsec = wireless_get_vapsec(wl, vapidx);

    if (!vsec || !value)
    {
        return -1;
    }

    vsec->wep_keyidx = atoi(value);
    return 0;
}


static int opt_parse_standard(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    char hwmode[10];
    char htmode[10];
    char option[UCI_MAX_STR_LEN];
    char ucival[UCI_MAX_STR_LEN+1] = {0};
    char device[UCI_MAX_STR_LEN+1] = {0};
    char orig_hwmode[UCI_MAX_STR_LEN + 1] = {0};
    // Translate standard into the format required for
    // "iwpriv athx mode" command.
    char wireless_htmode[IEEE80211_MAX_HTMODE_LEN];
    int ret;
    struct vapsec_s *vsec;

    memset(hwmode, 0, sizeof(hwmode));
    memset(htmode, 0, sizeof(htmode));
    memset(wireless_htmode, 0, sizeof(wireless_htmode));

    snprintf(option, sizeof(option), "@wifi-iface[%d].device", vapidx - 1);
    ret = uciGet(ctx, "wireless", option, device);
    if (ret || strlen(device) > IFNAMSIZ )
        return -1;

    snprintf(option, sizeof(option), "%s.hwmode", device);
    ret = uciGet(ctx, "wireless", option, orig_hwmode);
    if (ret) { return -1; }

    if (strcmp(value, "a") == 0 ||
        strcmp(value, "b") == 0 ||
        strcmp(value, "g") == 0)
    {
        snprintf(hwmode, sizeof(hwmode), "11%s", value);
    }
    else if (strcmp(value, "na20") == 0 )
    {
        strlcpy(hwmode, "11na", sizeof(hwmode));
        strlcpy(htmode, "HT20", sizeof(htmode));
        strlcpy(wireless_htmode, "11NAHT20", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "na40") == 0 )
    {
        strlcpy(hwmode, "11na", sizeof(hwmode));
        strlcpy(htmode, "HT40",  sizeof(htmode));
        strlcpy(wireless_htmode, "11NAHT40", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "na40plus") == 0 )
    {
        strlcpy(hwmode, "11na", sizeof(hwmode));
        strlcpy(htmode, "HT40+", sizeof(htmode));
        strlcpy(wireless_htmode, "11NAHT40PLUS", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "na40minus") == 0 )
    {
        strlcpy(hwmode, "11na", sizeof(hwmode));
        strlcpy(htmode, "HT40-", sizeof(htmode));
        strlcpy(wireless_htmode, "11NAHT40MINUS", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "ng20") == 0 )
    {
        strlcpy(hwmode, "11ng", sizeof(hwmode));
        strlcpy(htmode, "HT20", sizeof(htmode));
        strlcpy(wireless_htmode, "11NGHT20", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "ng40") == 0 )
    {
        strlcpy(hwmode, "11ng", sizeof(hwmode));
        strlcpy(htmode, "HT40", sizeof(htmode));
        strlcpy(wireless_htmode, "11NGHT40", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "ng40plus") == 0 )
    {
        strlcpy(hwmode, "11ng", sizeof(hwmode));
        strlcpy(htmode, "HT40+", sizeof(htmode));
        strlcpy(wireless_htmode, "11NGHT40PLUS", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "ng40minus") == 0 )
    {
        strlcpy(hwmode, "11ng", sizeof(hwmode));
        strlcpy(htmode, "HT40-", sizeof(htmode));
        strlcpy(wireless_htmode, "11NGHT40MINUS", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht20") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT20", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT20", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht40") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT40", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT40", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht40plus") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT40+", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT40PLUS", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht40minus") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT40-", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT40MINUS", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht80") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT80", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT80", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht160") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT160", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT160", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "acvht80_80") == 0 )
    {
        strlcpy(hwmode, "11ac", sizeof(hwmode));
        strlcpy(htmode, "HT80_80", sizeof(htmode));
        strlcpy(wireless_htmode, "11ACVHT80_80", sizeof(wireless_htmode));
    }
    else if (strcmp(value, "auto") == 0 )
    {
        // When Registrar is operating in AUTO mode, keep original hwmode and
        // set htmode to AUTO.
        strlcpy(hwmode, orig_hwmode, sizeof(hwmode));
        strlcpy(htmode, "AUTO", sizeof(htmode));
        strlcpy(wireless_htmode, "AUTO", sizeof(wireless_htmode));
    }
    else
    {
        printf("unhandled standard %s\n", value);
        return 0;
    }

    if (strcmp(hwmode, orig_hwmode))
    {
        ret = uciSet(ctx, "wireless", option , hwmode);
        wl->changed = true;
    }

    if (ret)
        return ret;

    if (!strlen(htmode))
        return 0;

    snprintf(option, sizeof(option), "%s.htmode", device);
    ret = uciGet(ctx, "wireless", option, ucival);
    if (ret ||
        strcmp(htmode, ucival))
    {
        ret = uciSet(ctx, "wireless", option , htmode);
        vsec = wireless_get_vapsec(wl, vapidx);
        if (!vsec) { return -1; }
        if (vsec->htmode) {
            free(vsec->htmode);
        }
        vsec->htmode = strdup(wireless_htmode);
        vsec->opti_changed = true;
    }
    return ret;
}


static int opt_parse_channel(struct uci_context *ctx, struct wireless_s *wl, int radioidx, char *name, char *value)
{
    char option[UCI_MAX_STR_LEN];
    char ucival[UCI_MAX_STR_LEN];
    char newval[UCI_MAX_STR_LEN];
    char device[UCI_MAX_STR_LEN];
    char vapphy[UCI_MAX_STR_LEN];
    int ret;
    bool foundvap = false;
    struct vapsec_s *vsec;

    if (strcmp(value, "0") == 0 )
       snprintf(newval, sizeof(newval), "auto");
    else
       snprintf(newval, UCI_MAX_STR_LEN, value);

    snprintf(device, sizeof(device), "wifi%d", radioidx -1);
    snprintf(option, sizeof(option), "%s.channel", device );

    ret = uciGet(ctx, "wireless", option, ucival);

    if (ret ||
        strcmp(newval, ucival))
    {
        ret = uciSet(ctx, "wireless", option , newval);
        /* set channel to vap if it exists*/
        vsec = wl->vsec;
        while (vsec)
        {
            snprintf(option, sizeof(option), "@wifi-iface[%d].device", vsec->vapidx - 1);
            ret = uciGet(ctx, "wireless", option, vapphy);
            if (ret == 0 && strcmp(device, vapphy) == 0) {
                if (vsec->channel)
                    free(vsec->channel);
                vsec->channel = strdup(newval);
                vsec->opti_changed = true;
                foundvap = true;
            }

            vsec = vsec->next;
        }

        /* As long as a VAP was found on which to set the channel for
         * this radio, use the optimized restart mechanism.
         *
         * If no VAP was found (which generally should not happen), do
         * a full restart even though it may not be strictly necessary.
         * This full restart is the conservative strategy in this unexpected
         * circumstance.
         */
        if (!foundvap)
        {
             wl->changed = true;
        }
    }

    return ret;
}

static int opt_parse_vapind(struct uci_context *ctx, struct wireless_s *wl, int vapidx, char *name, char *value)
{
    char option[UCI_MAX_STR_LEN];
    char ucival[UCI_MAX_STR_LEN];
    int ret;
    struct vapsec_s *vsec;

    snprintf(option, sizeof(option), "@wifi-iface[%d].athnewind", vapidx - 1);
    ret = uciGet(ctx, "wireless", option, ucival);

    if (ret ||
        strcmp(value, ucival))
    {
        ret = uciSet(ctx, "wireless", option , value);
        vsec = wireless_get_vapsec(wl, vapidx);
        if (!vsec)
        {
            return -1;
        }
        if (vsec->vapind)
            free(vsec->vapind);
        vsec->vapind = strdup(value);
        vsec->opti_changed = true;
    }

    return ret;
}



static struct wl_translate_option radioTbl[] =
{
    { "RdioEnabled",            "disabled",     opt_bool_revert,      NULL},
    { "Channel",                "channel",      NULL,                 NULL},
    { "ClonedChannel",          NULL,           NULL,                 opt_parse_channel},
    { "X_ATH-COM_Powerlevel",   "txpower",      NULL,                 NULL},
    { "X_ATH-COM_Rxchainmask",  "rxchainmask",  NULL,                 NULL},
    { "X_ATH-COM_Txchainmask",  "txchainmask",  NULL,                 NULL},
    { "X_ATH-COM_TBRLimit",     NULL,           NULL,                 NULL},
    { "ATH-COM_AMPDUEnabled",   "AMPDU",        NULL,                 NULL},
    { "X_ATH-COM_AMPDULimit",   "AMPDULim",     NULL,                 NULL},
    { "X_ATH-COM_AMPDUFrames",  NULL,           NULL,                 NULL},
    { NULL }
};

static struct wl_translate_option vapTbl[] =
{
    { "Enable",                       "disabled",     opt_bool_revert,         NULL },
    { "X_ATH-COM_RadioIndex",         "device",       opt_radidx_to_device,    NULL },
    { "SSID",                         "ssid",         NULL,                    NULL },
    { "BeaconType",                   NULL,           NULL,                    opt_parse_bcntype },
    { "Standard",                     NULL,           NULL,                    opt_parse_standard  },
    { "WEPKeyIndex",                  NULL,           NULL,                    opt_parse_wepkeyidx },
    { "KeyPassphrase",                NULL,           NULL,                    opt_parse_psk },
    { "BasicEncryptionModes",         NULL,           NULL,                    opt_parse_wepencr },
    { "BasicAuthenticationMode",      NULL,           NULL,                    opt_parse_wepauth },
    { "WPAEncryptionModes",           NULL,           NULL,                    opt_parse_wpaencr },
    { "WPAAuthenticationMode",        NULL,           NULL,                    opt_parse_wpaauth },
    { "IEEE11iEncryptionModes",       NULL,           NULL,                    opt_parse_11iencr },
    { "IEEE11iAuthenticationMode",    NULL,           NULL,                    opt_parse_11iauth },
    { "BasicDataTransmitRates",       "mcast_rate",   NULL,                    NULL },
    { "RTS",                          "rts",          NULL,                    NULL },
    { "Fragmentation",                "frag",         NULL,                    NULL },
    { "VAPIndependent",               "athnewind",    NULL,                    opt_parse_vapind },
    { "PeerBSSID",                    "bssid",        NULL,                    NULL },
    { "AuthenticationServiceMode",    NULL,           NULL,                    NULL },
    { "X_ATH-COM_EAPReauthPeriod",    "eap_reauth_period", NULL,               NULL },
    { "X_ATH-COM_WEPRekeyPeriod",     "wep_rekey",    NULL,                    NULL },
    { "X_ATH-COM_AuthServerAddr",     "auth_server",  NULL,                    NULL },
    { "X_ATH-COM_AuthServerPort",     "auth_port",    NULL,                    NULL },
    { "X_ATH-COM_AuthServerSecret",   "auth_secret",  NULL,                    NULL },
    { "X_ATH-COM_RSNPreAuth",         "rsn_preauth",  NULL,                    NULL },
    { "X_ATH-COM_SSIDHide",           "hidden",       NULL,                    NULL },
    { "X_ATH-COM_APModuleEnable",     NULL,           NULL,                    NULL },
    { "X_ATH-COM_WPSPin",             "wps_pin",      NULL,                    NULL },
    { "X_ATH-COM_WPSConfigured",      NULL,           NULL,                    NULL },
    { "X_ATH-COM_ShortGI",            "shortgi",      NULL,                    NULL },
    { "X_ATH-COM_CWMEnable",          NULL,           NULL,                    NULL },
    { "X_ATH-COM_WMM",                "wmm",          NULL,                    NULL },
    { "X_ATH-COM_HT40Coexist",        "disablecoext", opt_bool_revert,         NULL },
    { "X_ATH-COM_HBREnable",          NULL,           NULL,                    NULL },
    { "X_ATH-COM_HBRPERLow",          NULL,           NULL,                    NULL },
    { "X_ATH-COM_HBRPERHigh",         NULL,           NULL,                    NULL },
    { "X_ATH-COM_MEMode",             NULL,           NULL,                    NULL },
    { "X_ATH-COM_MELength",           NULL,           NULL,                    NULL },
    { "X_ATH-COM_METimer",            NULL,           NULL,                    NULL },
    { "X_ATH-COM_METimeout",          NULL,           NULL,                    NULL },
    { "X_ATH-COM_MEDropMcast",        NULL,           NULL,                    NULL },
    { "WEPKey.1.WEPKey",              "key1",         NULL,                    NULL },
    { "WEPKey.2.WEPKey",              "key2",         NULL,                    NULL },
    { "WEPKey.3.WEPKey",              "key3",         NULL,                    NULL },
    { "WEPKey.4.WEPKey",              "key4",         NULL,                    NULL },
    { "X_ATH-COM_GroupRekeyPeriod",  "wpa_group_rekey", NULL,                  NULL },
    { "PreSharedKey.1.PreSharedKey",  NULL,           NULL,                    opt_parse_psk },
    { "Channel",                      NULL,           NULL,                    NULL },
    { NULL }
};


static int wireless_set_radio(struct uci_context *ctx, struct wireless_s *wl, char *name, char *value)
{
    char option[UCI_MAX_STR_LEN];
    char ucival[UCI_MAX_STR_LEN];
    char newval[UCI_MAX_STR_LEN];
    int radidx;
    struct wl_translate_option *iopt;
    int ret;

    radidx = strtoul(name, &name, 0);
    if (!name || *name != '.')
    {
        return -1;
    }

    name ++;

    iopt = radioTbl;
    while(iopt->optname  != NULL)
    {
        if (strcmp(name, iopt->optname) == 0)
            break;
        iopt ++;
    }

    if (!iopt->optname)
    {
        printf("unhandled option %s\n", name);
        return 0;
    }

    if (iopt->optparser &&
        iopt->optparser(ctx, wl, radidx, name, value) != 0)
        return -1;

    if (!iopt->uciname)
        return 0;

    if (iopt->opt2uci)
    {
        if (iopt->opt2uci(value, newval) != 0)
            return -1;
        value = newval;
    }

    snprintf(option, sizeof(option), "wifi%d.%s",radidx - 1, iopt->uciname);

    ret = uciGet(ctx, "wireless", option, ucival);
    if (ret
        || strcmp(value, ucival))
    {
        ret = uciSet(ctx, "wireless", option , value);
        wl->changed = true;
    }

    return ret;
}


static int wireless_set_vap(struct uci_context *ctx, struct wireless_s *wl, char *name, char *value)
{
    char option[UCI_MAX_STR_LEN];
    char ucival[UCI_MAX_STR_LEN];
    char newval[UCI_MAX_STR_LEN];
    int vapidx;
    struct wl_translate_option *iopt;
    char *pos = NULL;
    int ret;
    struct vapsec_s *vsec;

    vapidx = strtoul(name, &pos, 0);
    if (!pos || *pos != '.')
    {
        return -1;
    }

    pos ++;

    iopt = vapTbl;
    while(iopt->optname  != NULL)
    {
        if (strcmp(pos, iopt->optname) == 0)
            break;
        iopt ++;
    }

    if (!iopt->optname)
    {
        printf("unhandled option %s\n", name);
        return -1;
    }

    if (iopt->optparser &&
        iopt->optparser(ctx, wl, vapidx, pos, value) != 0)
        return -1;

    if (!iopt->uciname)
    {
        return 0;
    }

    if (iopt->opt2uci)
    {
        if (iopt->opt2uci(value, newval) != 0)
            return -1;
        value = newval;
    }

    snprintf(option, sizeof(option), "@wifi-iface[%d].%s",vapidx - 1, iopt->uciname);

    ret = uciGet(ctx, "wireless", option, ucival);
    if ( ret ||
        strcmp(value, ucival))
    {
        ret = uciSet(ctx, "wireless", option , value);
        vsec = wireless_get_vapsec(wl, vapidx);
        if (vsec == NULL) /* no memory */
            return -1;
        vsec->changed = true;
    }

    return ret;
}

static int wireless_apply_optimized(struct vapsec_s *vsec)
{
    int vapind;
    int channel;

    if (!vsec->channel
        && !vsec->vapind
        && !vsec->htmode)
        return 0;

    if (strlen(vsec->ifname) <= 0
        && wireless_get_ifname_by_vapidx(vsec->vapidx, vsec->ifname) < 0)
    {
        return 0;
    }

    /*set channel*/
    if (vsec->channel)
    {
        channel = atoi(vsec->channel);
        if (!vsec->isdown)
        {
            wireless_vap_ifctl(vsec->ifname, 0);
            vsec->isdown = true;
        }

        if (wireless_set_vapchannel(vsec->ifname, channel)!= 0)
            perror("set channel failed\n");

    }
    /*set athnewind
      down-up is only needed when athnewind changed from 0->1, so that the AP vap
      could be changed to running state.
      If it is set to a STA, we need to wake up the ap in same radio.
    */
    if (vsec->vapind)
    {
        vapind = atoi(vsec->vapind);
        if (!vsec->isdown
            && atoi(vsec->vapind) == 1)
        {
            wireless_vap_ifctl(vsec->ifname, 0);
            vsec->isdown = true;
        }

        if (wireless_set_vapind(vsec->ifname, vapind) != 0)
            perror("set athnewind failed\n");
    }
    
    if (vsec->htmode)
    {
        if (!vsec->isdown)
        {
            wireless_vap_ifctl(vsec->ifname, 0);
            vsec->isdown = true;
        }
        if (wireless_set_vaphtmode(vsec->ifname, vsec->htmode) != 0)
            perror("set mode failed\n");
    }

    return 0;
}

static int wireless_apply_vapsec(void *cookie, struct package_s *pkg)
{
    struct wireless_s *wl = (struct wireless_s *)pkg->priv;
    struct uci_context *ctx = (struct uci_context *)cookie;
    struct vapsec_s *vsec = wl->vsec;
    int ret = 0;
    char option[UCI_MAX_STR_LEN];
    char ucival[UCI_MAX_STR_LEN];
    char newval[UCI_MAX_STR_LEN];

    memset(newval, 0, sizeof(newval));
    while (vsec)
    {
        /* wifi security */
        if (vsec->bcn_type == 0)
            goto next;

        /* option: encryption */
        switch (vsec->bcn_type)
        {
            case BEACONTYPE_eNone:
                snprintf(newval, UCI_MAX_STR_LEN, "none");
                break;
            case BEACONTYPE_eBasic:
                if (vsec->wep_auth == BASICAUTHENTICATIONMODE_eNone)
                    snprintf(newval, UCI_MAX_STR_LEN, "wep");
                else if (vsec->wep_auth == BASICAUTHENTICATIONMODE_eSharedAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "wep+shared");
                else if (vsec->wep_auth == BASICAUTHENTICATIONMODE_eEAPAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "8021x");
                else if (vsec->wep_auth == BASICAUTHENTICATIONMODE_eBoth)
                    snprintf(newval, UCI_MAX_STR_LEN, "wep+mixed");
                else
                    snprintf(newval, UCI_MAX_STR_LEN, "wep");
                break;
            case BEACONTYPE_eWPA:
                if (vsec->wpa2_auth == WPAAUTHENTICATIONMODE_eEAPAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "wpa");
                else if (vsec->wpa2_auth == WPAAUTHENTICATIONMODE_ePSKAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "psk");
                else
                    snprintf(newval, UCI_MAX_STR_LEN, "psk");

                if (vsec->wpa2_encr == WPAENCRYPTIONMODES_eTKIPEncryption)
                    snprintf(newval + 3, UCI_MAX_STR_LEN - 3, "+tkip");
                else if (vsec->wpa2_encr == WPAENCRYPTIONMODES_eAESEncryption)
                    snprintf(newval + 3, UCI_MAX_STR_LEN - 3, "+ccmp");
                if (vsec->wpa2_encr == WPAENCRYPTIONMODES_eTKIPandAESEncryption)
                    snprintf(newval + 3, UCI_MAX_STR_LEN - 3, "+tkip+ccmp");
                break;

            case BEACONTYPE_e11i:
                if (vsec->wpa2_auth == IEEE11IAUTHENTICATIONMODE_eEAPAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "wpa2");
                else if (vsec->wpa2_auth == IEEE11IAUTHENTICATIONMODE_ePSKAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "psk2");
                else if (vsec->wpa2_auth == IEEE11IAUTHENTICATIONMODE_eEAPandPSKAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "psk2"); /*not defined in uci*/
                else
                    snprintf(newval, UCI_MAX_STR_LEN, "psk2");

                if (vsec->wpa2_encr == IEEE11IENCRYPTIONMODES_eTKIPEncryption)
                    snprintf(newval + strlen(newval), UCI_MAX_STR_LEN - strlen(newval), "+tkip");
                else if (vsec->wpa2_encr == IEEE11IENCRYPTIONMODES_eAESEncryption)
                    snprintf(newval + strlen(newval), UCI_MAX_STR_LEN - strlen(newval), "+ccmp");
                if (vsec->wpa2_encr == IEEE11IENCRYPTIONMODES_eTKIPandAESEncryption)
                    snprintf(newval + strlen(newval), UCI_MAX_STR_LEN - strlen(newval), "+tkip+ccmp");

                break;
            case BEACONTYPE_eWPAand11i:
                if (vsec->wpa2_auth == IEEE11IAUTHENTICATIONMODE_eEAPAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "mixed-wpa");
                else if (vsec->wpa2_auth == IEEE11IAUTHENTICATIONMODE_ePSKAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "mixed-psk");
                else if (vsec->wpa2_auth == IEEE11IAUTHENTICATIONMODE_eEAPandPSKAuthentication)
                    snprintf(newval, UCI_MAX_STR_LEN, "mixed-psk");/*not defined in uci*/
                else
                    snprintf(newval, sizeof(newval),  "mixed-psk");

                if (vsec->wpa2_encr == IEEE11IENCRYPTIONMODES_eTKIPEncryption)
                    snprintf(newval + strlen(newval), UCI_MAX_STR_LEN - strlen(newval), "+tkip");
                else if (vsec->wpa2_encr == IEEE11IENCRYPTIONMODES_eAESEncryption)
                    snprintf(newval + strlen(newval), UCI_MAX_STR_LEN - strlen(newval), "+ccmp");
                if (vsec->wpa2_encr == IEEE11IENCRYPTIONMODES_eTKIPandAESEncryption)
                    snprintf(newval + strlen(newval), UCI_MAX_STR_LEN - strlen(newval), "+tkip+ccmp");

                break;
        }

        snprintf(option, sizeof(option), "@wifi-iface[%d].encryption", vsec->vapidx - 1);
        ret = uciGet(ctx, "wireless", option, ucival);
        if (ret ||
            strcmp(ucival, newval))
        {
            ret = uciSet(ctx, "wireless", option , newval);
            vsec->changed=true;
        }

        if (ret)
           break;

        /* option: key */
        memset(newval, 0, sizeof(newval));
        if (vsec->psk || vsec->passphrase || vsec->wep_keyidx)
        {
            if (vsec->bcn_type == BEACONTYPE_eBasic
                && vsec->wep_keyidx )
            {
                snprintf(newval, sizeof(newval), "%d", vsec->wep_keyidx);
            }
            else if (vsec->psk && strlen(vsec->psk))
            {
                snprintf(newval, sizeof(newval), "%s", vsec->psk);
            }
            else if (vsec->passphrase && strlen(vsec->passphrase))
            {
                snprintf(newval, sizeof(newval), "%s", vsec->passphrase);
            }

        }

        if (!strlen(newval))
            goto next;

        snprintf(option, sizeof(option), "@wifi-iface[%d].key", vsec->vapidx - 1);
        ret = uciGet(ctx, "wireless", option, ucival);
        if (ret ||
            strcmp(ucival, newval))
        {
            ret = uciSet(ctx, "wireless", option , newval);
            vsec->changed = true;
        }

        if (ret)
            break;

next:
        vsec = vsec->next;

    }/*for each vap*/

    return ret;
}

static int wireless_init(struct package_s *pkg)
{
    struct wireless_s *wl = (struct wireless_s *)pkg->priv;
    memset(wl, 0, sizeof(struct wireless_s));
    return 0;
}

static int wireless_set(void *cookie, struct package_s *pkg, char *name, char *value)
{
    struct wireless_s *wl = (struct wireless_s *)pkg->priv;
    struct uci_context *ctx = (struct uci_context *)cookie;
    int ret = 0;
    int fltlen;

    if (fltlen = strlen(pkg->flt1),
        memcmp(name, pkg->flt1, fltlen) == 0)
    {
        ret = wireless_set_radio(ctx, wl, name + fltlen, value);
    }
    else if (fltlen = strlen(pkg->flt2),
        memcmp(name, pkg->flt2, fltlen) == 0)
    {
        ret = wireless_set_vap(ctx, wl, name + fltlen, value);
    }
    else
    {
        ret = -1;
    }

    return ret;
}

static bool wireless_reset_vap_flags(void *cookie, struct package_s *pkg,
                                     char *radio,const char *delim)
{
    bool ret = true;
    struct wireless_s *wl = (struct wireless_s *)pkg->priv;
    struct uci_context *ctx = (struct uci_context *)cookie;
    struct vapsec_s *vsec = wl->vsec;
    char vapphy[UCI_MAX_STR_LEN] = {0};
    char option[UCI_MAX_STR_LEN] = {0};
    char *token = NULL;

    token = strtok(radio,delim);
    while(token != NULL)
    {
        vsec = wl->vsec;
        while(vsec)
        {
            snprintf(option, sizeof(option), "@wifi-iface[%d].device", vsec->vapidx - 1);
            ret = uciGet(ctx, "wireless", option, vapphy);
            if(!strcmp(token,vapphy))
            {
                vsec->isdown = false;
            }
            vsec = vsec->next;
        }
        token = strtok(NULL,delim);
    }
    return ret;
}

static int wireless_apply(void *cookie, struct package_s *pkg)
{
    struct wireless_s *wl = (struct wireless_s *)pkg->priv;
    struct uci_context *ctx = (struct uci_context *)cookie;
    struct vapsec_s *vsec = wl->vsec;
    char vapphy[UCI_MAX_STR_LEN + 1] = {0};
    char option[UCI_MAX_STR_LEN] = {0};
    char radio[UCI_MAX_STR_LEN + 1] = {0};
    char *p = NULL;
    char buf[UCI_MAX_STR_LEN * 2];
    int ret = 0;
    bool need_vap_restart = false;
    const char *delim = " ";

    if (wireless_apply_vapsec(ctx, pkg))
        return -1;
    ret = uciCommit(ctx, pkg->name);
    if(wl->changed)
    { /* phy related parameter changed , restarting all radios */
        system("/sbin/wifi");
        return ret;
    }

    while (vsec)
    {
        if (vsec->changed)
        {
            snprintf(option, sizeof(option), "@wifi-iface[%d].device", vsec->vapidx - 1);
            ret = uciGet(ctx, "wireless", option, vapphy);
            p = strstr(radio,vapphy);
            if( p == NULL )
            { /*unique radio name */
                if (strlen(radio) + strlen(vapphy) + strlen(delim) + 1 < sizeof(radio))
                {
                    strlcat(radio, vapphy, sizeof(radio) - strlen(radio));
                    strlcat(radio, delim, sizeof(radio) - strlen(radio));
                    memset(vapphy,0,sizeof(vapphy));
                    p = NULL;
                }
                else
                {
                    fprintf(stderr," Too many interfaces \n");
                    fprintf(stderr," restarting All radios \n");
                    system("/sbin/wifi");
                    return ret;
                }
            }
        }
        else if(vsec->opti_changed)
        {
            need_vap_restart = true;
            wireless_apply_optimized(vsec);
        }

        vsec = vsec->next;
    } /* while loop for vsec*/

    if (strlen(radio))
    {
        snprintf(buf, sizeof(buf), "/sbin/wifi up '%s'",radio);
        wireless_reset_vap_flags(cookie,pkg,radio,delim);
        system(buf);
    }

    if(need_vap_restart)
    { /* up vap to apply*/
        vsec = wl->vsec;
        while (vsec)
        {
            if (vsec->isdown)
            {
                wireless_vap_ifctl(vsec->ifname, 1);
                vsec->isdown = false;
            }
            vsec = vsec->next;
        }
    }
    return ret;
}

static int wireless_destroy(struct package_s *pkg)
{
    struct wireless_s *wl = (struct wireless_s *)pkg->priv;
    wireless_free_vapsec(wl);
    return 0;
}


static struct package_s wirelessPkg =
{
    "wireless",        /*name*/
    wireless_init,     /*init*/
    wireless_set,      /*set*/
    NULL,              /*get*/
    wireless_apply,    /*apply*/
    wireless_destroy,  /*destroy*/
    "RADIO.",          /*flt1*/
    "WLAN.",           /*flt2*/
    NULL,              /*priv*/
    NULL               /*next*/
};


int wireless_register()
{
    struct wireless_s *wl = malloc(sizeof(struct wireless_s));

    if (! wl)
        return -1;

    memset(wl, 0, sizeof(struct wireless_s));

    wirelessPkg.priv = (void *)wl;

    pkgRegister(&wirelessPkg);

    return 0;
}



