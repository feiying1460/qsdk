/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

/*
 * Regulatory domain and DFS implementation
 */

#include <osdep.h>
#include <ieee80211_regdmn.h>
#include <ieee80211_channel.h>

#if UMAC_SUPPORT_REGDMN
static int
ieee80211_set_countrycode(struct ieee80211com *ic, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd);
static int
ieee80211_set_11d_countrycode(struct ieee80211com *ic, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd);
static void
ieee80211_build_countryie_all(struct ieee80211com *ic);
static void regdmn_populate_channel_list_from_map(regdmn_op_class_map_t *map,
                                           u_int8_t reg_class, struct ieee80211_node *ni);


static void wlan_notify_country_changed(void *arg, wlan_if_t vap) 
{
    char *country = (char*)arg;
    IEEE80211_DELIVER_EVENT_COUNTRY_CHANGE(vap, country);
}

/*
 * Set country code
 */
int
ieee80211_set_country_code(struct ieee80211com *ic, char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    int  error;
    IEEE80211_COUNTRY_ENTRY ctry;

    if (!cc) {
        if (isoName != NULL) {
            ic->ic_get_currentCountry(ic, &ctry);
            if((ic->ic_country_iso[0] == isoName[0]) &&
            (ic->ic_country_iso[1] == isoName[1]) &&
            (ic->ic_country_iso[2] == isoName[2]) &&
            (ic->ic_country.iso[0] == isoName[0]) &&
            (ic->ic_country.iso[1] == isoName[1]) &&
            (ic->ic_country.iso[2] == isoName[2]) &&
            (ctry.iso[0] == isoName[0]) &&
            (ctry.iso[1] == isoName[1]) &&
            (ctry.iso[2] == isoName[2])) {
                return 0;
            }
        }
    }

    IEEE80211_DISABLE_11D(ic);

    error = ic->ic_set_country(ic, isoName, cc, cmd);
    if (error)
        return error;

    /* update the country information for 11D */
    ic->ic_get_currentCountry(ic, &ic->ic_country);

    /* update channel list */
    ieee80211_update_channellist(ic, 1);
    
    ic->ic_country_iso[0] = ic->ic_country.iso[0];
    ic->ic_country_iso[1] = ic->ic_country.iso[1];
    ic->ic_country_iso[2] = ic->ic_country.iso[2];

    ieee80211_build_countryie_all(ic);

    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
        IEEE80211_ENABLE_11D(ic);
    }

#if ATH_SUPPORT_ZERO_CAC_DFS
    ieee80211_reset_precaclists(ic);
#endif
    /* notify all vaps that the country changed */
    wlan_iterate_vap_list(ic, wlan_notify_country_changed, (void *)ic->ic_country.iso);

    return 0;
}

void
ieee80211_update_spectrumrequirement(struct ieee80211vap *vap)
{
    /*
     * 1. If not multiple-domain capable, check to update the country IE.
     * 2. If multiple-domain capable,
     *    a. If the country has been set by using desired country,
     *       then it is done, the ie has been updated.
     *       For IBSS or AP mode, if we are DFS owner, then need to enable Radar detect.
     *    b. If the country is not set, if no AP or peer country info,
     *       just assuming legancy mode.
     *       If we have AP or peer country info, using default to see if AP accept for now.
     */
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = vap->iv_bss;
    IEEE80211_COUNTRY_ENTRY curCountry;

    ieee80211_ic_doth_clear(ic);

    if (ic->ic_country.isMultidomain == 0) {
        if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
            if (!IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
                ic->ic_country_iso[0] = ic->ic_country.iso[0];
                ic->ic_country_iso[1] = ic->ic_country.iso[1];
                ic->ic_country_iso[2] = ic->ic_country.iso[2];

                ieee80211_build_countryie_all(ic);
            }
            ieee80211_ic_doth_set(ic);
        }
        return;
    }

    if (IEEE80211_HAS_DESIRED_COUNTRY(ic)) {
        /* If the country has been set, enabled the flag */
        if( (ic->ic_country_iso[0] == ni->ni_cc[0]) &&
            (ic->ic_country_iso[1] == ni->ni_cc[1])) {
            if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
                ieee80211_ic_doth_set(ic);
            }
            IEEE80211_ENABLE_11D(ic);
            return;
        }
    }

    if ((ni->ni_cc[0] == 0)   ||
        (ni->ni_cc[1] == 0)   ||
        (ni->ni_cc[0] == ' ') ||
        (ni->ni_cc[1] == ' ')) {
        if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
            ieee80211_ic_doth_set(ic);
        }            
        return;
    }

    // Update the cc only for platforms that request this : Currently, only Windows.
    if (ieee80211_ic_disallowAutoCCchange_is_set(ic)) {
        ic->ic_get_currentCountry(ic, &curCountry);
        if ((ni->ni_cc[0] == curCountry.iso[0] && 
             ni->ni_cc[1] == curCountry.iso[1] &&
             ni->ni_cc[2] == curCountry.iso[2]))  
        {
            ieee80211_build_countryie_all(ic);
            if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
                ieee80211_ic_doth_set(ic);
            }
        }
    }
    else {
        // If ignore11dBeacon, using the original reg. domain setting.
        if (!IEEE80211_IS_11D_BEACON_IGNORED(ic)) {
            if (ieee80211_set_country_code(ic, (char*)ni->ni_cc, 0, CLIST_UPDATE) == 0) {
                if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT)
                    ieee80211_ic_doth_set(ic);
            }
        }
    }
    
}

int
ieee80211_update_country_allowed(struct ieee80211com *ic)
{
    if (IEEE80211_IS_11D_BEACON_IGNORED(ic))
        return 0;
    return ic->ic_country.isMultidomain;
}

void
ieee80211_set_regclassids(struct ieee80211com *ic, const u_int8_t *regclassids, u_int nregclass)
{
    int i;
    
    if (nregclass >= IEEE80211_REGCLASSIDS_MAX)
        nregclass = IEEE80211_REGCLASSIDS_MAX;

    ic->ic_nregclass = nregclass;
    
    for (i = 0; i < nregclass; i++)
        ic->ic_regclassids[i] = regclassids[i];
}

/*
 * Build the country information element.
 */
void
ieee80211_build_countryie(struct ieee80211vap *vap)
{
    struct country_ie_triplet *pTriplet;
    struct ieee80211_channel *c;
    int i, j, chanflags, chancnt, isnewband;
    u_int8_t *chanlist;
    u_int8_t prevchan;
    struct ieee80211com *ic = vap->iv_ic;

    if (!ic->ic_country_iso[0] || !ic->ic_country_iso[1] || !ic->ic_country_iso[2]) {
        /* Default, no country is set */
        vap->iv_country_ie_data.country_len = 0;
        IEEE80211_DISABLE_COUNTRYIE(ic);
        return;
    }

    IEEE80211_ENABLE_COUNTRYIE(ic);

    /*
     * Construct the country IE:
     * 1. The country string come first.
     * 2. Then construct the channel triplets from lowest channel to highest channel.
     * 3. If we support the regulatory domain class (802.11J)
     *    then add the class triplets before the channel triplets of each band.
     */
    OS_MEMZERO(&vap->iv_country_ie_data, sizeof(vap->iv_country_ie_data));  
    vap->iv_country_ie_data.country_id = IEEE80211_ELEMID_COUNTRY;
    vap->iv_country_ie_data.country_len = 3;

    vap->iv_country_ie_data.country_str[0] = ic->ic_country_iso[0];
    vap->iv_country_ie_data.country_str[1] = ic->ic_country_iso[1];
    vap->iv_country_ie_data.country_str[2] = ic->ic_country_iso[2];

    pTriplet = (struct country_ie_triplet*)&vap->iv_country_ie_data.country_triplet;

    if(IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        chanflags = IEEE80211_CHAN_2GHZ;
    else
        chanflags = IEEE80211_CHAN_5GHZ;

    vap->iv_country_ie_chanflags = chanflags;

    chanlist = OS_MALLOC(ic->ic_osdev, sizeof(u_int8_t) * (IEEE80211_CHAN_MAX + 1), 0);
    if (chanlist == NULL) {
        /* Default, no country is set */
        vap->iv_country_ie_data.country_len = 0;
        IEEE80211_DISABLE_COUNTRYIE(ic);
        return;
    }

    OS_MEMZERO(chanlist, sizeof(uint8_t) * (IEEE80211_CHAN_MAX + 1));
    prevchan = 0;
    chancnt = 0;
    isnewband = 1;
    ieee80211_enumerate_channels(c, ic, i) {
        /* Does channel belong to current operation mode */
        if (!(c->ic_flags & chanflags))
            continue;

        /* Skip previously reported channels */
        for (j=0; j < chancnt; j++) {
            if (c->ic_ieee == chanlist[j])
                break;
        }
    
        if (j != chancnt) /* found a match */
            continue;

        chanlist[chancnt] = c->ic_ieee;
        chancnt++;

        /* Skip turbo channels */
        if (IEEE80211_IS_CHAN_TURBO(c))
            continue;

        if (ic->ic_no_weather_radar_chan 
                && (ieee80211_check_weather_radar_channel(c))
                && (DFS_ETSI_DOMAIN  == ic->ic_get_dfsdomain(ic))) 
        {
            /* skipping advertising weather radar channels */
            continue;
        }

        /* Skip half/quarter rate channels */
        if (IEEE80211_IS_CHAN_HALF(c) || 
                IEEE80211_IS_CHAN_QUARTER(c))
            continue;

        if (isnewband) {
            isnewband = 0;
        } else if ((pTriplet->maxtxpwr == c->ic_maxregpower) && (c->ic_ieee == prevchan + 1)) {
            pTriplet->nchan ++;
            prevchan = c->ic_ieee;
            continue;
        } else {
            pTriplet ++;
        }

        prevchan = c->ic_ieee;
        pTriplet->schan = c->ic_ieee;
        pTriplet->nchan = 1; /* init as 1 channel */
        pTriplet->maxtxpwr = c->ic_maxregpower;
        vap->iv_country_ie_data.country_len += 3;
    }

    /* pad */
    if (vap->iv_country_ie_data.country_len & 1) {
        vap->iv_country_ie_data.country_triplet[vap->iv_country_ie_data.country_len] = 0;
        vap->iv_country_ie_data.country_len++;
    }

    OS_FREE(chanlist);
}

static void
ieee80211_build_countryie_vap(void *arg,struct ieee80211vap *vap, bool is_last_vap)
{
    ieee80211_build_countryie(vap);
}

/*
* update the country ie in all vaps.
*/
static void
ieee80211_build_countryie_all(struct ieee80211com *ic)
{
    u_int8_t num_vaps;
    ieee80211_iterate_vap_list_internal(ic,ieee80211_build_countryie_vap,NULL,num_vaps);
}

static int
ieee80211_set_countrycode(struct ieee80211com *ic, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    if (ieee80211_set_country_code(ic, isoName, cc, cmd)) {
        IEEE80211_CLEAR_DESIRED_COUNTRY(ic);
        return -EINVAL;
    }
    
    if (!cc) {
        if ((isoName == NULL) || (isoName[0] == '\0') || (isoName[1] == '\0')) {
            IEEE80211_CLEAR_DESIRED_COUNTRY(ic);
        } else {
            IEEE80211_SET_DESIRED_COUNTRY(ic);
        }
    } else {
        IEEE80211_SET_DESIRED_COUNTRY(ic);
    }

    return 0;
}

static int
ieee80211_set_11d_countrycode(struct ieee80211com *ic, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    if (!ic->ic_country.isMultidomain)
        return -EINVAL;
    return ieee80211_set_countrycode(ic, isoName, cc, cmd);
}

int
ieee80211_regdmn_reset(struct ieee80211com *ic)
{
    char cc[3];

    /* Reset to default country if any. */
    cc[0] = cc[1] = cc[2] = 0;
    ieee80211_set_countrycode(ic, cc, 0, CLIST_UPDATE);
    ic->ic_multiDomainEnabled = 0;

    return 0;
}

#endif

int
wlan_set_countrycode(wlan_dev_t devhandle, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    return ieee80211_set_countrycode(devhandle, isoName, cc, cmd);
}

int
wlan_get_countrycode(wlan_dev_t devhandle, char cc[3])
{
    OS_MEMCPY(cc, devhandle->ic_country.iso, 3);
    return 0;
}

int
wlan_set_11d_countrycode(wlan_dev_t devhandle, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    return ieee80211_set_11d_countrycode(devhandle, isoName, cc, cmd);
}

u_int16_t
wlan_get_regdomain(wlan_dev_t devhandle)
{
    return devhandle->ic_country.regDmnEnum;
}

int
wlan_set_regdomain(wlan_dev_t devhandle, u_int16_t regdmn)
{
    struct ieee80211com *ic = devhandle;
    int error;

    error = ic->ic_set_regdomain(ic, regdmn);
    if (!error)
        ic->ic_country.regDmnEnum = regdmn;

    return error;
}

u_int8_t
wlan_get_ctl_by_country(wlan_dev_t devhandle, u_int8_t *country, bool is2G)
{
    struct ieee80211com *ic = devhandle;
    return ic->ic_get_ctl_by_country(ic, country, is2G);
}


/* US Operating Classes */
regdmn_op_class_map_t us_operating_class[] = {
    {1,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48}},
    {2,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {52, 56, 60, 64}},
    {4,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}},
    {5,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {149, 153, 157, 161, 165}},
    {22,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {36, 44}},
    {23,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {52, 60}},
    {24,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {100, 108, 116, 124, 132, 140}},
    {25,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {149, 157}},
    {27,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {40, 48}},
    {28,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {56, 64}},
    {29,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {104, 112, 120, 128, 136, 144}},
    {31,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {153, 161}},
    {32,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {1, 2, 3, 4, 5, 6, 7}},
    {33,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {5, 6, 7, 8, 9, 10, 11}},
    {128, IEEE80211_CWM_WIDTH80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
           132, 136, 140, 144, 149, 153, 157, 161}},
    {129, IEEE80211_CWM_WIDTH160, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {130, IEEE80211_CWM_WIDTH80_80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
           132, 136, 140, 144, 149, 153, 157, 161}},
    {0, 0, 0, {0}},
};

/* Europe operating classes */
regdmn_op_class_map_t europe_operating_class[] = {
    {1,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48}},
    {2,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {52, 56, 60, 64}},
    {3,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}},
    {4,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {5,   IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {36, 44}},
    {6,   IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {52, 60}},
    {7,   IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {100, 108, 116, 124, 132}},
    {8,   IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {40, 48}},
    {9,   IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {56, 64}},
    {10,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {104, 112, 120, 128, 136}},
    {11,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {1, 2, 3, 4, 5, 6, 7, 8, 9}},
    {12,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {17,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {149, 153, 157, 161, 165, 169}},
    {128, IEEE80211_CWM_WIDTH80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {129, IEEE80211_CWM_WIDTH160, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {130, IEEE80211_CWM_WIDTH80_80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {0, 0, 0, {0}},
};

/* Japan operating classes */
regdmn_op_class_map_t japan_operating_class[] = {
    {1,   IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48}},
    {30,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {31,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {14}},
    {32,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {52, 56, 60, 64}},
    {34,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}},
    {36,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {36, 44}},
    {37,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {52, 60}},
    {39,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {100, 108, 116, 124, 132}},
    {41,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {40, 48}},
    {42,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {56, 64}},
    {44,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {104, 112, 120, 128, 136}},
    {128, IEEE80211_CWM_WIDTH80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128} },
    {129, IEEE80211_CWM_WIDTH160, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {130, IEEE80211_CWM_WIDTH80_80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {0, 0, 0, {0}},
};

/* Global operating classes */
regdmn_op_class_map_t global_operating_class[] = {
    {81,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {82,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {14}},
    {83,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {1, 2, 3, 4, 5, 6, 7, 8, 9}},
    {84,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {115, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48}},
    {116, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {36, 44}},
    {117, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {40, 48}},
    {118, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {52, 56, 60, 64}},
    {119, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {52, 60}},
    {120, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {56, 64}},
    {121, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}},
    {122, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {100, 108, 116, 124, 132, 140}},
    {123, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {104, 112, 120, 128, 136, 144}},
    {125, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {149, 153, 157, 161, 165, 169}},
    {126, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {149, 157}},
    {127, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {153, 161}},
    {128, IEEE80211_CWM_WIDTH80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
           132, 136, 140, 144, 149, 153, 157, 161}},
    {129, IEEE80211_CWM_WIDTH160, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {130, IEEE80211_CWM_WIDTH80_80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
           132, 136, 140, 144, 149, 153, 157, 161}},
    {0, 0, 0, {0}},
};

void get_regdmn_op_class_map(struct ieee80211com *ic, regdmn_op_class_map_t **map) {

    uint8_t *country_iso = &(ic->ic_country_iso[0]);

    if (!qdf_mem_cmp(country_iso, "US", 2)) {
      *map = us_operating_class;
    } else if (!qdf_mem_cmp(country_iso, "EU", 2)) {
      *map = europe_operating_class;
    } else if (!qdf_mem_cmp(country_iso, "JP", 2)) {
      *map = japan_operating_class;
    } else {
      *map = global_operating_class;
    }

    return;
}

uint8_t
regdmn_get_new_opclass_from_channel(struct ieee80211com *ic,
                                    struct ieee80211_channel *channel)
{
    uint8_t chan = channel->ic_ieee;
    uint8_t ch_width = 0;
    regdmn_op_class_map_t *map = NULL;
    uint8_t idx = 0;

    ch_width = ieee80211_get_cwm_width_from_channel(channel);

    // Get the regdmn map corresponding to country code
    get_regdmn_op_class_map(ic, &map);

    while (map->op_class) {
       if (ch_width == map->ch_width) {
            for (idx = 0; idx < MAX_CHANNELS_PER_OPERATING_CLASS; idx++) {
                if (map->ch_set[idx] == chan) {
                    /* Find exact promary and seconday match for 40 MHz channel */
                    if (ch_width == IEEE80211_CWM_WIDTH40) {
                        /* Compare HT40+/HT40- mode */
                        if (map->sec20_offset == ieee80211_sec_chan_offset(channel)) {
                            return map->op_class;
                        }
                    } else {
                        return map->op_class;
                    }
                }
            }
        }
        map++;
    }
    /* operating class could not be found. return 0. */
    return 0;
}

uint8_t
regdmn_get_band_cap_from_op_class(struct ieee80211com *ic,
                                  uint8_t num_of_opclass, const uint8_t *opclass)
{
    regdmn_op_class_map_t *map = NULL;
    uint8_t  opclassidx = 0, supported_band = 0; // Invalid band

    // Get the regdmn map corresponding to country code
    get_regdmn_op_class_map(ic, &map);

    while (map->op_class) {
        for (opclassidx = 0; opclassidx < num_of_opclass; opclassidx++) {
            if (map->op_class == opclass[opclassidx]) {
                if (map->ch_set[0] >= IEEE80211_MIN_2G_CHANNEL &&
                                map->ch_set[0] <= IEEE80211_MAX_2G_CHANNEL) {
                    supported_band |= (1 << IEEE80211_2G_BAND);

                } else if (map->ch_set[0] >= IEEE80211_MIN_5G_CHANNEL &&
                                 map->ch_set[0] <= IEEE80211_MAX_5G_CHANNEL) {
                    supported_band |= (1 << IEEE80211_5G_BAND);

                }
                break;
            }
        }
        map++;
    }
    return supported_band;
}

void regdmn_populate_channel_list_from_map(regdmn_op_class_map_t *map,
                                  u_int8_t reg_class, struct ieee80211_node *ni) {
    uint8_t chanidx = 0;

    if(!map)
        return;

    while (map->op_class) {
        if (map->op_class == reg_class) {
            for (chanidx = 0; chanidx < MAX_CHANNELS_PER_OPERATING_CLASS &&
                                map->ch_set[chanidx] != 0; chanidx++) {
                ni->ni_supp_op_cl.channels_supported[map->ch_set[chanidx]] = true;

            }
            ni->ni_supp_op_cl.num_chan_supported += chanidx;
            break;
        }
        map++;
    }
    return;
}

void
regdmn_get_channel_list_from_op_class(uint8_t reg_class,
                                      struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    regdmn_op_class_map_t *map = NULL;

    // Get the regdmn map corresponding to country code
    get_regdmn_op_class_map(ic, &map);
    regdmn_populate_channel_list_from_map(map, reg_class, ni);

    /* Check for global operating class and mark those channels also as true to
     * pass MBO related testcase.
     */
    if (map != global_operating_class) {
        regdmn_populate_channel_list_from_map(global_operating_class, reg_class, ni);
    }

    return;
}

uint8_t
regdmn_get_opclass (struct ieee80211com *ic)
{
    uint8_t *country_iso = ic->ic_country_iso;
    struct ieee80211_channel *channel = ic->ic_curchan;
    uint8_t ch_width = ieee80211_get_cwm_width_from_channel(channel);
    regdmn_op_class_map_t *map;
    uint8_t idx;

    /* If operating class table index is specified in the country code per
     * 802.11 Annex E, derive operating class table from it. Otherwise use 
     * country_iso name 
     */ 
    if (country_iso[2] == 0x01) {
        map = us_operating_class;
    } else if (country_iso[2] == 0x02) {
        map = europe_operating_class;
    } else if (country_iso[2] == 0x03) {
        map = japan_operating_class;
    } else if (country_iso[2] == 0x04) {
        map = global_operating_class;
    } else if (country_iso[2] == 0x05) {
        map = europe_operating_class;
    } else {
        get_regdmn_op_class_map(ic, &map);
    }

    while (map->op_class) {
       if (ch_width == map->ch_width) {
            for (idx = 0; idx < MAX_CHANNELS_PER_OPERATING_CLASS; idx++) {
                if (map->ch_set[idx] == channel->ic_ieee) {
                    /* Find exact promary and seconday match for 40 MHz channel */
                    if (ch_width == IEEE80211_CWM_WIDTH40) {
                        /* Compare HT40+/HT40- mode */
                        if (map->sec20_offset == ieee80211_sec_chan_offset(channel)) {
                            return map->op_class;
                        }
                    } else {
                        return map->op_class;
                    }
                }
            }
        }
        map++;
    }

    /* operating class could not be found. return 0. */
    return 0;
}
