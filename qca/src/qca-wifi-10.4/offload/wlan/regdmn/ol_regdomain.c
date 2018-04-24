/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * Notifications and licenses are retained for attribution purposes only.
 */
/*
 * Copyright (c) 2002-2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2005-2006 Atheros Communications, Inc.
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the following conditions are met:
 * 1. The materials contained herein are unmodified and are used
 *    unmodified.
 * 2. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following NO
 *    ''WARRANTY'' disclaimer below (''Disclaimer''), without
 *    modification.
 * 3. Redistributions in binary form must reproduce at minimum a
 *    disclaimer similar to the Disclaimer below and any redistribution
 *    must be conditioned upon including a substantially similar
 *    Disclaimer requirement for further binary redistribution.
 * 4. Neither the names of the above-listed copyright holders nor the
 *    names of any contributors may be used to endorse or promote
 *    product derived from this software without specific prior written
 *    permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT,
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

#include "ol_if_athvar.h"

#include "athdefs.h"
#include "ol_defines.h"
#include "ol_if_ath_api.h"
#include "ol_helper.h"
#include "wlan_defs.h"
#include "qdf_mem.h"

#include "ol_regdomain.h"

/* used throughout this file... */
#define    N(a)    (sizeof (a) / sizeof (a[0]))

/* 10MHz is half the 11A bandwidth used to determine upper edge freq
   of the outdoor channel */
#define HALF_MAXCHANBW        10

/* Mask to check whether a domain is a multidomain or a single
   domain */

#define MULTI_DOMAIN_MASK 0xFF00

#define    WORLD_SKU_MASK        0x00F0
#define    WORLD_SKU_PREFIX    0x0060

/* Global configuration overrides */
static    const int countrycode = -1;
static    const int xchanmode = -1;
static    const int ath_outdoor = AH_FALSE;        /* enable outdoor use */
static    const int ath_indoor  = AH_FALSE;        /* enable indoor use  */
static    int ath_table = 0;                       /* Operating class table
                                                      index per Appendix E */

int
ol_ath_pdev_set_regdomain(ol_scn_t scn, struct ol_regdmn *ol_regdmn_handle)
{
    struct pdev_set_regdomain_params param;

    qdf_mem_set(&param, sizeof(param), 0);
    param.currentRDinuse = ol_regdmn_handle->ol_regdmn_currentRDInUse ;
    param.currentRD2G = ol_regdmn_handle->ol_regdmn_currentRD2G;
    param.currentRD5G = ol_regdmn_handle->ol_regdmn_currentRD5G;
    param.ctl_2G = ol_regdmn_handle->ol_regdmn_ctl_2G;
    param.ctl_5G = ol_regdmn_handle->ol_regdmn_ctl_5G;
    param.dfsDomain = ol_regdmn_handle->ol_regdmn_dfsDomain;

    return wmi_unified_pdev_set_regdomain_cmd_send(scn->wmi_handle, &param);
}

bool ol_regdmn_set_regdomain(struct ol_regdmn* ol_regdmn_handle, REGDMN_REG_DOMAIN regdomain)
{
    ol_regdmn_handle->ol_regdmn_current_rd = regdomain;

    return true;
}

bool ol_regdmn_set_regdomain_ext(struct ol_regdmn* ol_regdmn_handle, REGDMN_REG_DOMAIN regdomain)
{
    ol_regdmn_handle->ol_regdmn_current_rd_ext = regdomain;
    return true;
}

bool ol_regdmn_get_regdomain(struct ol_regdmn* ol_regdmn_handle, REGDMN_REG_DOMAIN *regdomain)
{
    *regdomain = ol_regdmn_handle->ol_regdmn_current_rd;
    return true;
}
/* Helper function to get hardware wireless capabilities */
u_int ol_regdmn_getWirelessModes(struct ol_regdmn* ol_regdmn_handle)
{
    return ol_regdmn_handle->scn_handle->hal_reg_capabilities.wireless_modes;
}

#ifdef OL_ATH_DUMP_RD_SPECIFIC_CHANNELS

void inline
ol_ath_dump_channel_entry(
	struct ieee80211_channel * channel
	)
{
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, 
		"%4d %08X      %02X     %03d         %02d       %02d"
		"       %02X         %02d     %02d   %02d   %02d ",
		channel->ic_freq,
		channel->ic_flags,
		channel->ic_flagext,
		channel->ic_ieee,
		channel->ic_maxregpower,
		channel->ic_maxpower,
		channel->ic_minpower,
		channel->ic_regClassId,
		channel->ic_antennamax,
		channel->ic_vhtop_ch_freq_seg1,
		channel->ic_vhtop_ch_freq_seg2
		);

	if( channel->ic_flags & IEEE80211_CHAN_TURBO )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "TURBO ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_CCK )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CCK ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_OFDM )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "OFDM ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_2GHZ )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "2G ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_5GHZ )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "5G ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_PASSIVE )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "PSV ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_DYN )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "DYN ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_GFSK )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "GFSK ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_RADAR )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "RDR ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_STURBO )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "STURBO ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_HALF )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HALF ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_QUARTER )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "QUARTER ");
	}


	if( channel->ic_flags & IEEE80211_CHAN_HT20 )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT20 ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_HT40PLUS )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT40+ ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_HT40MINUS )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT40- ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_HT40INTOL )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "HT40INTOL ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_VHT20 )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT20 ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_VHT40PLUS )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT40+ ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_VHT40MINUS )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT40- ");
	}


	if( channel->ic_flags & IEEE80211_CHAN_VHT80 )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT80 ");
	}

	if( channel->ic_flags & IEEE80211_CHAN_VHT160 )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT160 ");
	}
	if( channel->ic_flags & IEEE80211_CHAN_VHT80_80 )
	{
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "VHT80_80 ");
	}
	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\n");

}

void inline
ol_ath_dump_rd_specific_channels(
	struct ieee80211com *ic,
	struct ol_regdmn *ol_regdmn_handle
	)
{
	struct ieee80211_channel *chans = ic->ic_channels;
	uint32_t i;

	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\tXXXXXX RegDomain specific channel list XXXXXX\n");

	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, 
		"RD: %X, RD(in use): %X, CCODE: %s (%X)\n",
		ol_regdmn_handle->ol_regdmn_current_rd,
		ol_regdmn_handle->ol_regdmn_currentRDInUse,
		ol_regdmn_handle->ol_regdmn_iso,
		ol_regdmn_handle->ol_regdmn_countryCode
		);

	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, 
		"freq    flags flagext IEEE No. maxregpwr "
		"maxtxpwr mintxpwr regclassID antmax "
		"seg1 seg2\n"
		);

	for( i = 0; i < ic->ic_nchans; i++ )
	{
		ol_ath_dump_channel_entry( &chans[i] );
	}
}

#endif

int
ol_regdmn_getchannels(struct ol_regdmn *ol_regdmn_handle, u_int cc,
                bool outDoor, bool xchanMode, IEEE80211_REG_PARAMETERS *reg_parm)
{
    ol_scn_t scn_handle;
    struct ieee80211com *ic;
    struct ieee80211_channel *chans;
    int nchan;
    u_int8_t regclassids[ATH_REGCLASSIDS_MAX];
    u_int nregclass = 0;
    u_int wMode;
    u_int netBand;
    u_int i;
    struct ol_ath_softc_net80211 *scn;

    scn_handle = ol_regdmn_handle->scn_handle;
    ic = &scn_handle->sc_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    wMode = reg_parm->wModeSelect;

    if (!(wMode & REGDMN_MODE_11A)) {
        wMode &= ~(REGDMN_MODE_TURBO|REGDMN_MODE_108A|REGDMN_MODE_11A_HALF_RATE);
    }
    if (!(wMode & REGDMN_MODE_11G)) {
        wMode &= ~(REGDMN_MODE_108G);
    }

    netBand = reg_parm->netBand;
    if (!(netBand & REGDMN_MODE_11A)) {
        netBand &= ~(REGDMN_MODE_TURBO|REGDMN_MODE_108A|REGDMN_MODE_11A_HALF_RATE);
    }
    if (!(netBand & REGDMN_MODE_11G)) {
        netBand &= ~(REGDMN_MODE_108G);
    }
    wMode &= netBand;

    chans = ic->ic_channels;

    if (chans == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to allocate channel table\n", __func__);
        return -ENOMEM;
    }

    /*
     * remove some of the modes based on different compile time
     * flags.
     */

    if (!ol_regdmn_init_channels(ol_regdmn_handle, chans, IEEE80211_CHAN_MAX, (u_int *)&nchan,
                               regclassids, ATH_REGCLASSIDS_MAX, &nregclass,
                               cc, wMode, outDoor, xchanMode,
                               scn->sc_is_blockdfs_set)) {
        u_int32_t rd;

        rd = ol_regdmn_handle->ol_regdmn_current_rd;
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to collect channel list from regdomain; "
               "regdomain likely %u country code %u\n",
               __func__, rd, cc);
        return -EINVAL;
    }

    for (i=0; i<nchan; i++) {
        chans[i].ic_maxpower = scn_handle->max_tx_power;
        chans[i].ic_minpower = scn_handle->min_tx_power;
    }

    ol_80211_channel_setup(ic, CLIST_UPDATE,
                           chans, nchan, regclassids, nregclass,
                           CTRY_DEFAULT);

#ifdef OL_ATH_DUMP_RD_SPECIFIC_CHANNELS
	ol_ath_dump_rd_specific_channels(ic, ol_regdmn_handle);
#endif

    ol_ath_pdev_set_regdomain(scn_handle, ol_regdmn_handle);

    return 0;
}

void
ol_regdmn_start(struct ol_regdmn *ol_regdmn_handle, IEEE80211_REG_PARAMETERS *reg_parm )
{
    ol_scn_t scn_handle;
    REGDMN_REG_DOMAIN rd;
    int error;

    scn_handle = ol_regdmn_handle->scn_handle;

    ol_regdmn_get_regdomain(ol_regdmn_handle, &rd);

	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO
		"%s: reg-domain param: regdmn=%X, countryName=%s, wModeSelect=%X, netBand=%X, extendedChanMode=%X.\n",
		__func__,
		reg_parm->regdmn,
    	reg_parm->countryName,
    	reg_parm->wModeSelect,
    	reg_parm->netBand,
    	reg_parm->extendedChanMode
		);

    if (reg_parm->regdmn) {
        // Set interface regdmn configuration
        ol_regdmn_set_regdomain(ol_regdmn_handle, reg_parm->regdmn);
    }

    ol_regdmn_handle->ol_regdmn_countryCode = CTRY_DEFAULT;

    if (countrycode != -1) {
        ol_regdmn_handle->ol_regdmn_countryCode = countrycode;
    }

    if ((rd == 0) && reg_parm->countryName[0]) {
        ol_regdmn_handle->ol_regdmn_countryCode = ol_regdmn_findCountryCode((u_int8_t *)reg_parm->countryName);
    }

   if (xchanmode != -1) {
        ol_regdmn_handle->ol_regdmn_xchanmode = xchanmode;
    } else {
        ol_regdmn_handle->ol_regdmn_xchanmode = reg_parm->extendedChanMode;
    }

    ol_regdmn_handle->ol_regdmn_ch144 = 0;

    error = ol_regdmn_getchannels(ol_regdmn_handle, ol_regdmn_handle->ol_regdmn_countryCode,
                            ath_outdoor, ol_regdmn_handle->ol_regdmn_xchanmode, reg_parm);

    if (error != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,  "%s[%d]: Failed to get channel information! error[%d]\n", __func__, __LINE__, error );
    }

}

void
ol_regdmn_detach(struct ol_regdmn* ol_regdmn_handle)
{
    if (ol_regdmn_handle != NULL) {
        OS_FREE(ol_regdmn_handle);
        ol_regdmn_handle = NULL;
    }
}

/*
 * Store the channel edges for the requested operational mode
 */
bool
ol_get_channel_edges(struct ol_regdmn* ol_regdmn_handle,
    u_int16_t flags, u_int16_t *low, u_int16_t *high)
{
    TARGET_HAL_REG_CAPABILITIES *p_cap = &ol_regdmn_handle->scn_handle->hal_reg_capabilities;

    if (flags & IEEE80211_CHAN_5GHZ) {
        *low = p_cap->low_5ghz_chan;
        *high = p_cap->high_5ghz_chan;
        return true;
    }
    if ((flags & IEEE80211_CHAN_2GHZ)) {
        *low = p_cap->low_2ghz_chan;
        *high = p_cap->high_2ghz_chan;

        return true;
    }
    return false;
}

static int
chansort(const void *a, const void *b)
{
#define CHAN_FLAGS    (IEEE80211_CHAN_ALL)
    const struct ieee80211_channel *ca = a;
    const struct ieee80211_channel *cb = b;

    return (ca->ic_freq == cb->ic_freq) ?
        (ca->ic_flags & CHAN_FLAGS) -
            (cb->ic_flags & CHAN_FLAGS) :
        ca->ic_freq - cb->ic_freq;
#undef CHAN_FLAGS
}

typedef int ath_hal_cmp_t(const void *, const void *);
static    void ath_hal_sort(void *a, u_int32_t n, u_int32_t es, ath_hal_cmp_t *cmp);
static const COUNTRY_CODE_TO_ENUM_RD* findCountry(REGDMN_CTRY_CODE countryCode, REGDMN_REG_DOMAIN rd);
static bool getWmRD(struct ol_regdmn* ol_regdmn_handle, int regdmn, u_int16_t channelFlag, REG_DOMAIN *rd);
static bool ol_regdmn_duplicate_channel(struct ieee80211_channel *chan, struct ieee80211_channel *list, int size);

#define isWwrSKU(_ol_regdmn_handle) (((getEepromRD((_ol_regdmn_handle)) & WORLD_SKU_MASK) == WORLD_SKU_PREFIX) || \
               (getEepromRD(_ol_regdmn_handle) == WORLD))

#define isWwrSKU_NoMidband(_ol_regdmn_handle) ((getEepromRD((_ol_regdmn_handle)) == WOR3_WORLD) || \
                (getEepromRD(_ol_regdmn_handle) == WOR4_WORLD) || \
                (getEepromRD(_ol_regdmn_handle) == WOR5_ETSIC))
#define isUNII1OddChan(ch) ((ch == 5170) || (ch == 5190) || (ch == 5210) || (ch == 5230))

/*
 * By default, the regdomain tables reference the common tables
 * from ah_regdomain_common.h.  These default tables can be replaced
 * by calls to populate_regdomain_tables functions.
 */

HAL_REG_DMN_TABLES ol_regdmn_Rdt = {
    ahCmnRegDomainPairs,    /* regDomainPairs */
    AH_NULL,                /* regDmnVendorPairs */
    ahCmnAllCountries,      /* allCountries */
    AH_NULL,                /* customMappings */
    ahCmnRegDomains,        /* regDomains */

    N(ahCmnRegDomainPairs),    /* regDomainPairsCt */
    0,                         /* regDmnVendorPairsCt */
    N(ahCmnAllCountries),      /* allCountriesCt */
    0,                         /* customMappingsCt */
    N(ahCmnRegDomains),        /* regDomainsCt */
};


static u_int16_t
getEepromRD(struct ol_regdmn* ol_regdmn_handle)
{
    return ol_regdmn_handle->ol_regdmn_current_rd &~ WORLDWIDE_ROAMING_FLAG;
}

/*
 * Test to see if the bitmask array is all zeros
 */
static bool
isChanBitMaskZero(u_int64_t *bitmask)
{
    int i;

    for (i=0; i<BMLEN; i++) {
        if (bitmask[i] != 0)
            return false;
    }
    return true;
}

/*
 * Return whether or not the regulatory domain/country in EEPROM
 * is acceptable.
 */
static bool
isEepromValid(struct ol_regdmn* ol_regdmn_handle)
{
    u_int16_t rd = getEepromRD(ol_regdmn_handle);
    int i;

    if (rd & COUNTRY_ERD_FLAG) {
        u_int16_t cc = rd &~ COUNTRY_ERD_FLAG;
        for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++)
            if (ol_regdmn_Rdt.allCountries[i].countryCode == cc)
                return true;
    } else {
        for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++)
            if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == rd)
                return true;
    }
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: invalid regulatory domain/country code 0x%x\n",
        __func__, rd);
    return false;
}

#if !(_MAVERICK_STA_ || __NetBSD_) /* Apple EEPROMs do not have the Midband bit set */
/*
 * Return whether or not the FCC Mid-band flag is set in EEPROM
 */
static bool
isFCCMidbandSupported(struct ol_regdmn* ol_regdmn_handle)
{
    u_int32_t regcap;
    ol_scn_t scn_handle;

    scn_handle = ol_regdmn_handle->scn_handle;

    regcap = scn_handle->hal_reg_capabilities.regcap2;

    if (regcap & REGDMN_EEPROM_EEREGCAP_EN_FCC_MIDBAND) {
        return true;
    }
    else {
        return false;
    }
}
#endif /* !(_MAVERICK_STA_ || __NetBSD_) */

static const REG_DMN_PAIR_MAPPING *
getRegDmnPair(REGDMN_REG_DOMAIN reg_dmn)
{
    int i;
    for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++) {
        if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == reg_dmn) {
            return &ol_regdmn_Rdt.regDomainPairs[i];
        }
    }
    return AH_NULL;
}

/*
 * Returns whether or not the specified country code
 * is allowed by the EEPROM setting
 */
static bool
isCountryCodeValid(struct ol_regdmn* ol_regdmn_handle, REGDMN_CTRY_CODE cc)
{
    u_int16_t  rd;
    int i, support5G, support2G;
    u_int modesAvail;
    const COUNTRY_CODE_TO_ENUM_RD *country = AH_NULL;
    const REG_DMN_PAIR_MAPPING *regDmn_eeprom, *regDmn_input;

    /* Default setting requires no checks */
    if (cc == CTRY_DEFAULT || cc & COUNTRY_ERD_FLAG)
        return true;
#ifdef AH_DEBUG_COUNTRY
    if (cc == CTRY_DEBUG)
        return true;
#endif
    rd = getEepromRD(ol_regdmn_handle);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: EEPROM regdomain 0x%x\n", __func__, rd);

    if (rd & COUNTRY_ERD_FLAG) {
        /* EEP setting is a country - config shall match */
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: EEPROM setting is country code %u\n",
            __func__, rd &~ COUNTRY_ERD_FLAG);
        return (cc == (rd & ~COUNTRY_ERD_FLAG));
    }


    for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
        if (cc == ol_regdmn_Rdt.allCountries[i].countryCode) {
#ifdef REGDMN_SUPPORT_11D
            if ((rd & WORLD_SKU_MASK) == WORLD_SKU_PREFIX) {
                return true;
            }
#endif
            country = &ol_regdmn_Rdt.allCountries[i];
            if (country->regDmnEnum == rd ||
                rd == DEBUG_REG_DMN || rd == NO_ENUMRD) {
                return true;
            }
        }
    }
    if (country == AH_NULL) return false;

    /* consider device capability and look into the regdmn for 2G&5G */
    modesAvail = ol_regdmn_getWirelessModes(ol_regdmn_handle);
    support5G = modesAvail & (REGDMN_MODE_11A | REGDMN_MODE_TURBO |
                REGDMN_MODE_108A | REGDMN_MODE_11A_HALF_RATE |
                REGDMN_MODE_11A_QUARTER_RATE |
                REGDMN_MODE_11NA_HT40PLUS |
                REGDMN_MODE_11NA_HT40MINUS);
    support2G = modesAvail & (REGDMN_MODE_11G | REGDMN_MODE_11B | REGDMN_MODE_PUREG |
                REGDMN_MODE_108G |
                REGDMN_MODE_11NG_HT40PLUS |
                REGDMN_MODE_11NG_HT40MINUS);

    regDmn_eeprom = getRegDmnPair(rd);
    regDmn_input = getRegDmnPair(country->regDmnEnum);
    if (!regDmn_eeprom || !regDmn_input)
        return false;

    if (support5G && support2G) {
        /* force a strict binding between regdmn and countrycode */
        return false;
    } else if (support5G) {
        if (regDmn_eeprom->regDmn5GHz == regDmn_input->regDmn5GHz)
            return true;
    } else if (support2G) {
        if (regDmn_eeprom->regDmn2GHz == regDmn_input->regDmn2GHz)
            return true;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: neither 2G nor 5G is supported\n", __func__);
    }
    return false;
}

/*
 * Return the mask of available modes based on the hardware
 * capabilities and the specified country code and reg domain.
 */
static u_int
ol_regdmn_getwmodesnreg(struct ol_regdmn* ol_regdmn_handle, const COUNTRY_CODE_TO_ENUM_RD *country,
             REG_DOMAIN *rd5GHz)
{
    u_int modesAvail;

    /* Get modes that HW is capable of */
    modesAvail = ol_regdmn_getWirelessModes(ol_regdmn_handle);

    /* Check country regulations for allowed modes */
#ifndef ATH_NO_5G_SUPPORT
    if ((modesAvail & (REGDMN_MODE_11A_TURBO|REGDMN_MODE_TURBO)) &&
        (!country->allow11aTurbo))
        modesAvail &= ~(REGDMN_MODE_11A_TURBO | REGDMN_MODE_TURBO);
#endif
    if ((modesAvail & REGDMN_MODE_11G_TURBO) &&
        (!country->allow11gTurbo))
        modesAvail &= ~REGDMN_MODE_11G_TURBO;
    if ((modesAvail & REGDMN_MODE_11G) &&
        (!country->allow11g))
        modesAvail &= ~REGDMN_MODE_11G;
#ifndef ATH_NO_5G_SUPPORT
    if ((modesAvail & REGDMN_MODE_11A) &&
        (isChanBitMaskZero(rd5GHz->chan11a)))
        modesAvail &= ~REGDMN_MODE_11A;
#endif

    if ((modesAvail & REGDMN_MODE_11NG_HT20) &&
       (!country->allow11ng20))
        modesAvail &= ~REGDMN_MODE_11NG_HT20;

    if ((modesAvail & REGDMN_MODE_11NA_HT20) &&
       (!country->allow11na20))
        modesAvail &= ~REGDMN_MODE_11NA_HT20;

    if ((modesAvail & REGDMN_MODE_11NG_HT40PLUS) &&
       (!country->allow11ng40))
        modesAvail &= ~REGDMN_MODE_11NG_HT40PLUS;

    if ((modesAvail & REGDMN_MODE_11NG_HT40MINUS) &&
       (!country->allow11ng40))
        modesAvail &= ~REGDMN_MODE_11NG_HT40MINUS;

    if ((modesAvail & REGDMN_MODE_11NA_HT40PLUS) &&
       (!country->allow11na40))
        modesAvail &= ~REGDMN_MODE_11NA_HT40PLUS;

    if ((modesAvail & REGDMN_MODE_11NA_HT40MINUS) &&
       (!country->allow11na40))
        modesAvail &= ~REGDMN_MODE_11NA_HT40MINUS;

    if ((modesAvail & REGDMN_MODE_11AC_VHT20) &&
       (!country->allow11na20))
        modesAvail &= ~REGDMN_MODE_11AC_VHT20;

    if ((modesAvail & REGDMN_MODE_11AC_VHT40PLUS) &&
        (!country->allow11na40))
        modesAvail &= ~REGDMN_MODE_11AC_VHT40PLUS;

    if ((modesAvail & REGDMN_MODE_11AC_VHT40MINUS) &&
        (!country->allow11na40))
        modesAvail &= ~REGDMN_MODE_11AC_VHT40MINUS;

    if ((modesAvail & REGDMN_MODE_11AC_VHT80) &&
        (!country->allow11na80))
        modesAvail &= ~REGDMN_MODE_11AC_VHT80;

    if ((modesAvail & REGDMN_MODE_11AC_VHT160) &&
        (!country->allow11na160))
        modesAvail &= ~REGDMN_MODE_11AC_VHT160;

    if ((modesAvail & REGDMN_MODE_11AC_VHT80_80) &&
        (!country->allow11na80_80))
        modesAvail &= ~REGDMN_MODE_11AC_VHT80_80;

    return modesAvail;
}

/*
 * Return the mask of available modes based on the hardware
 * capabilities and the specified country code.
 */

u_int __ahdecl
ol_regdmn_getwirelessmodes(struct ol_regdmn* ol_regdmn_handle, REGDMN_CTRY_CODE cc)
{
    const COUNTRY_CODE_TO_ENUM_RD *country=AH_NULL;
    u_int mode=0;
    REG_DOMAIN rd;

    country = findCountry(cc, getEepromRD(ol_regdmn_handle));
    if (country != AH_NULL) {
        if (getWmRD(ol_regdmn_handle, country->regDmnEnum, ~IEEE80211_CHAN_2GHZ, &rd))
            mode = ol_regdmn_getwmodesnreg(ol_regdmn_handle, country, &rd);
    }
    return(mode);
}

/*
 * Return if device is public safety.
 */
bool __ahdecl
ol_regdmn_ispublicsafetysku(struct ol_regdmn* ol_regdmn_handle)
{
    u_int16_t rd;

    rd = getEepromRD(ol_regdmn_handle);

    switch (rd) {
        case FCC4_FCCA:
        case (CTRY_UNITED_STATES_FCC49 | COUNTRY_ERD_FLAG):
            return true;

        case DEBUG_REG_DMN:
        case NO_ENUMRD:
            if (ol_regdmn_handle->ol_regdmn_countryCode ==
                        CTRY_UNITED_STATES_FCC49) {
                return true;
            }
            break;
    }

    return false;
}


/*
 * Find the country code.
 */
REGDMN_CTRY_CODE __ahdecl
ol_regdmn_findCountryCode(u_int8_t *countryString)
{
    int i;

    for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
        if ((ol_regdmn_Rdt.allCountries[i].isoName[0] == countryString[0]) &&
            (ol_regdmn_Rdt.allCountries[i].isoName[1] == countryString[1]))
            return (ol_regdmn_Rdt.allCountries[i].countryCode);
    }
    return (0);        /* Not found */
}


/*
 * Find the country code for current regulatory domain
 */
REGDMN_CTRY_CODE __ahdecl
ol_regdmn_findCountryCodeForCurrentRD(u_int8_t *countryString, REGDMN_REG_DOMAIN curRd)
{
    int i;
    REGDMN_CTRY_CODE retCC=0;

    for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
        if ((ol_regdmn_Rdt.allCountries[i].isoName[0] == countryString[0]) &&
            (ol_regdmn_Rdt.allCountries[i].isoName[1] == countryString[1]))
            {
                // For backward compatibility --
                // Record first match and return this value if no matching country code
                // is found for current reg domain.
                if(retCC == 0)
                    retCC = ol_regdmn_Rdt.allCountries[i].countryCode;

                if(curRd == ol_regdmn_Rdt.allCountries[i].regDmnEnum)
                    return ol_regdmn_Rdt.allCountries[i].countryCode;

            }
    }
    return (retCC);        /* Not found */
}


/*
 * Find the conformance_test_limit by country code.
 */
u_int8_t __ahdecl
ol_regdmn_findCTLByCountryCode(REGDMN_CTRY_CODE ol_regdmn_countrycode, bool is2G)
{
    int i = 0, j = 0, k = 0;

    if  (ol_regdmn_countrycode == 0) {
        return NO_CTL;
    }

     for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
        if (ol_regdmn_Rdt.allCountries[i].countryCode == ol_regdmn_countrycode) {
            for (j = 0; j < ol_regdmn_Rdt.regDomainPairsCt; j++) {
                if (ol_regdmn_Rdt.regDomainPairs[j].regDmnEnum == ol_regdmn_Rdt.allCountries[i].regDmnEnum) {
                    for (k = 0; k < ol_regdmn_Rdt.regDomainsCt; k++) {
                        if (is2G) {
                             if (ol_regdmn_Rdt.regDomains[k].regDmnEnum == ol_regdmn_Rdt.regDomainPairs[j].regDmn2GHz)
                                 return ol_regdmn_Rdt.regDomains[k].conformance_test_limit;
                        } else {
                             if (ol_regdmn_Rdt.regDomains[k].regDmnEnum == ol_regdmn_Rdt.regDomainPairs[j].regDmn5GHz)
                                 return ol_regdmn_Rdt.regDomains[k].conformance_test_limit;
                        }
                    }
                }
            }
        }
    }

    return NO_CTL;
}


/*
 * Find the pointer to the country element in the country table
 * corresponding to the country code
 */
static const COUNTRY_CODE_TO_ENUM_RD*
findCountry(REGDMN_CTRY_CODE countryCode, REGDMN_REG_DOMAIN rd)
{
    int i;
    int ret_index = -1;


    for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
        if (ol_regdmn_Rdt.allCountries[i].countryCode == countryCode) {
            if(ret_index == -1)
            {
                // For backward compatibility
                // This will ensure first matched value will
                // be returned if reg domain does not match
                ret_index = i;
            }
            if(ol_regdmn_Rdt.allCountries[i].regDmnEnum == rd)
                return (&ol_regdmn_Rdt.allCountries[i]);
        }
    }

    if(ret_index == -1)
        return (AH_NULL);        /* Not found */
    else
        return (&ol_regdmn_Rdt.allCountries[ret_index]);
}

/*
 * Calculate a default country based on the EEPROM setting.
 */
static REGDMN_CTRY_CODE
getDefaultCountry(struct ol_regdmn* ol_regdmn_handle)
{
    u_int16_t rd;
    int i;

    rd =getEepromRD(ol_regdmn_handle);
    if (rd & COUNTRY_ERD_FLAG) {
        const COUNTRY_CODE_TO_ENUM_RD *country=AH_NULL;
        u_int16_t cc= rd & ~COUNTRY_ERD_FLAG;

        country = findCountry(cc, rd);
        if (country != AH_NULL)
            return cc;
    }
    /*
     * Check reg domains that have only one country
     */
    for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++) {
        if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == rd) {
            if (ol_regdmn_Rdt.regDomainPairs[i].singleCC != 0) {
                return ol_regdmn_Rdt.regDomainPairs[i].singleCC;
            } else {
                i = ol_regdmn_Rdt.regDomainPairsCt;
            }
        }
    }
    return CTRY_DEFAULT;
}

/*
 * Convert Country / RegionDomain to RegionDomain
 * rd could be region or country code.
*/
REGDMN_REG_DOMAIN
ol_regdmn_getDomain(struct ol_regdmn *ol_regdmn_handle, u_int16_t rd)
{
    if (rd & COUNTRY_ERD_FLAG) {
        const COUNTRY_CODE_TO_ENUM_RD *country=AH_NULL;
        u_int16_t cc= rd & ~COUNTRY_ERD_FLAG;

        country = findCountry(cc, rd);
        if (country != AH_NULL)
            return country->regDmnEnum;
        return 0;
    }
    return rd;
}

static bool
isValidRegDmn(int reg_dmn, REG_DOMAIN *rd)
{
    int i;

    for (i = 0; i < ol_regdmn_Rdt.regDomainsCt; i++) {
        if (ol_regdmn_Rdt.regDomains[i].regDmnEnum == reg_dmn) {
            if (rd != AH_NULL) {
                OS_MEMCPY(rd, &ol_regdmn_Rdt.regDomains[i], sizeof(REG_DOMAIN));
            }
            return true;
        }
    }
    return false;
}

static bool
isValidRegDmnPair(int regDmnPair)
{
    int i;

    if (regDmnPair == NO_ENUMRD) return false;
    for (i = 0; i < ol_regdmn_Rdt.regDomainPairsCt; i++) {
        if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == regDmnPair) return true;
    }
    return false;
}

/*
 * Return the Wireless Mode Regulatory Domain based
 * on the country code and the wireless mode.
 */
static bool
getWmRD(struct ol_regdmn *ol_regdmn_handle, int reg_dmn, u_int16_t channelFlag, REG_DOMAIN *rd)
{
    int i, found;
    u_int64_t flags=NO_REQ;
    const REG_DMN_PAIR_MAPPING *regPair=AH_NULL;
    int regOrg;

    regOrg = reg_dmn;
    if (reg_dmn == CTRY_DEFAULT) {
        u_int16_t rdnum;
        rdnum =getEepromRD(ol_regdmn_handle);

        if (!(rdnum & COUNTRY_ERD_FLAG)) {
            if (isValidRegDmn(rdnum, AH_NULL) ||
                isValidRegDmnPair(rdnum)) {
                reg_dmn = rdnum;
            }
        }
    }

    if ((reg_dmn & MULTI_DOMAIN_MASK) == 0) {

        for (i = 0, found = 0; (i < ol_regdmn_Rdt.regDomainPairsCt) && (!found); i++) {
            if (ol_regdmn_Rdt.regDomainPairs[i].regDmnEnum == reg_dmn) {
                regPair = &ol_regdmn_Rdt.regDomainPairs[i];
                found = 1;
            }
        }
        if (!found) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Failed to find reg domain pair %u\n",
                 __func__, reg_dmn);
            return false;
        }
        if (!(channelFlag & IEEE80211_CHAN_2GHZ)) {
            reg_dmn = regPair->regDmn5GHz;
            flags = regPair->flags5GHz;
        }
        if (channelFlag & IEEE80211_CHAN_2GHZ) {
            reg_dmn = regPair->regDmn2GHz;
            flags = regPair->flags2GHz;
        }
    }

    /*
     * We either started with a unitary reg domain or we've found the
     * unitary reg domain of the pair
     */

    found = isValidRegDmn(reg_dmn, rd);
    if (!found) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Failed to find unitary reg domain %u\n",
             __func__, reg_dmn);
        return false;
    } else {
        if (regPair == AH_NULL) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: No set reg domain pair\n", __func__);
            return false;
        }
        rd->pscan &= regPair->pscanMask;
        if (((regOrg & MULTI_DOMAIN_MASK) == 0) &&
            (flags != NO_REQ)) {
            rd->flags = flags;
        }
        /*
         * Use only the domain flags that apply to the current mode.
         * In particular, do not apply 11A Adhoc flags to b/g modes.
         */
        rd->flags &= (channelFlag & IEEE80211_CHAN_2GHZ) ?
            REG_DOMAIN_2GHZ_MASK : REG_DOMAIN_5GHZ_MASK;
        return true;
    }
}

static bool
IS_BIT_SET(int bit, u_int64_t *bitmask)
{
    int byteOffset, bitnum;
    u_int64_t val;

    byteOffset = bit/64;
    bitnum = bit - byteOffset*64;
    val = ((u_int64_t) 1) << bitnum;
    if (bitmask[byteOffset] & val)
        return true;
    else
        return false;
}

/* Add given regclassid into regclassids array upto max of maxregids */
static void
ath_add_regclassid(u_int8_t *regclassids, u_int maxregids, u_int *nregids, u_int8_t regclassid)
{
    int i;

    /* Is regclassid valid? */
    if (regclassid == 0)
        return;

    for (i=0; i < maxregids; i++) {
        if (regclassids[i] == regclassid)
            return;
        if (regclassids[i] == 0)
            break;
    }

    if (i == maxregids)
        return;
    else {
        regclassids[i] = regclassid;
        *nregids += 1;
    }

    return;
}

static bool
getEepromRegExtBits(struct ol_regdmn* ol_regdmn_handle, REG_EXT_BITMAP bit)
{
    return ((ol_regdmn_handle->ol_regdmn_current_rd_ext & (1<<bit))? true : false);
}


#define IS_HT40_MODE(_mode)      \
                    (((_mode == REGDMN_MODE_11NA_HT40PLUS  || \
                     _mode == REGDMN_MODE_11NG_HT40PLUS    || \
                     _mode == REGDMN_MODE_11NA_HT40MINUS   || \
                     _mode == REGDMN_MODE_11NG_HT40MINUS) ? true : false))

#define IS_VHT40_MODE(_mode)      \
                    (((_mode == REGDMN_MODE_11AC_VHT40PLUS  || \
                     _mode == REGDMN_MODE_11AC_VHT40MINUS) ? true : false))

#define IS_VHT80_MODE(_mode) ((_mode == REGDMN_MODE_11AC_VHT80) ? true : false)
#define IS_VHT160_MODE(_mode) ((_mode == REGDMN_MODE_11AC_VHT160) ? true : false)
#define IS_VHT80_80_MODE(_mode) ((_mode == REGDMN_MODE_11AC_VHT80_80) ? true : false)

/*
 * Setup the channel list based on the information in the EEPROM and
 * any supplied country code.  Note that we also do a bunch of EEPROM
 * verification here and setup certain regulatory-related access
 * control data used later on.
 */
#define OL_REGDMN_VHT80_CHAN_MAX 8
#define OL_REGDMN_VHT160_CMN_CHAN_MAX 24

struct ol_regdmn_vht80_chan {
    u_int16_t   vht80_ch[OL_REGDMN_VHT80_CHAN_MAX];
    u_int16_t   n_vht80_ch;
};

/* Common structure to contain members for channels with 160 bandwidth i.e. 160 and 80+80 */
struct ol_regdmn_vht160_cmn_chan {
    u_int16_t   n_vht160_cmn_ch;
    u_int16_t   vht160_cmn_ch[OL_REGDMN_VHT160_CMN_CHAN_MAX][2];
};

struct ol_regdmn_vht_sec_80_chan {
    u_int16_t sec_chan;
    const REG_DMN_FREQ_BAND *fband;
};

struct ol_regdmn_vht80_chan vht80_chans;
struct ol_regdmn_vht160_cmn_chan vht160_chans;
struct ol_regdmn_vht160_cmn_chan vht80_80_chans;
struct ol_regdmn_vht_sec_80_chan sec_80_chans[50];
u_int16_t sec_channel_count=0;

static void
ol_regdmn_init_vht80_chan(struct ol_regdmn_vht80_chan *ol_regdmn_vht80_chans)
{
    ol_regdmn_vht80_chans->n_vht80_ch = 0;
}

static void
ol_regdmn_init_vht160_chan(struct ol_regdmn_vht160_cmn_chan *ol_regdmn_vht160_chans)
{
    ol_regdmn_vht160_chans->n_vht160_cmn_ch = 0;
}
static void
ol_regdmn_init_vht80_80_chan(struct ol_regdmn_vht160_cmn_chan *ol_regdmn_vht160_cmn_chans)
{
    ol_regdmn_vht160_cmn_chans->n_vht160_cmn_ch = 0;
}
static void
ol_regdmn_add_vht80_chan(struct ol_regdmn_vht80_chan *ol_regdmn_vht80_chans, u_int16_t vht80_ch)
{
    bool duplicate = false;
    u_int16_t i = 0;

    if(ol_regdmn_vht80_chans->n_vht80_ch < OL_REGDMN_VHT80_CHAN_MAX) {
        for (i=0; i<ol_regdmn_vht80_chans->n_vht80_ch; i++) {
            if (ol_regdmn_vht80_chans->vht80_ch[i] == vht80_ch)
                duplicate = true;
        }
        if (!duplicate) {
            ol_regdmn_vht80_chans->vht80_ch[ol_regdmn_vht80_chans->n_vht80_ch++] = vht80_ch;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"Add VHT80 channel: %d\n", vht80_ch);
        }
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[%s][%d] vht80_ch overlimit=%d\n", __func__, __LINE__, OL_REGDMN_VHT80_CHAN_MAX);
    }
}

static void
ol_regdmn_add_vht160_cmn_chan(struct ol_regdmn_vht160_cmn_chan *ol_regdmn_vht160_cmn_chans, u_int16_t pri80_cfreq, u_int16_t sec80_cfreq)
{
    bool duplicate = false;
    u_int16_t i = 0;

    if(ol_regdmn_vht160_cmn_chans->n_vht160_cmn_ch < OL_REGDMN_VHT160_CMN_CHAN_MAX) {
        for (i=0; i < ol_regdmn_vht160_cmn_chans->n_vht160_cmn_ch; i++) {
            if (ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0] == pri80_cfreq && ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1] == sec80_cfreq) {
                duplicate = true;
                break;
            }

        }
        if (!duplicate) {
            ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[ol_regdmn_vht160_cmn_chans->n_vht160_cmn_ch][0] = pri80_cfreq;
            ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[ol_regdmn_vht160_cmn_chans->n_vht160_cmn_ch++][1] = sec80_cfreq;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_DEBUG"Add VHT160/VHT80_80 pri80 and sec80 centers: %d,%d\n", pri80_cfreq, sec80_cfreq);
        }
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[%s][%d] vht160_cmn_ch overlimit=%d\n", __func__, __LINE__, OL_REGDMN_VHT160_CMN_CHAN_MAX);
    }
}

static bool ol_regdmn_find_vht80_chan(struct ol_regdmn_vht80_chan *ol_regdmn_vht80_chans, u_int16_t ch, u_int16_t *vht80_ch)
{
    u_int16_t i;

    for( i = 0; i < ol_regdmn_vht80_chans->n_vht80_ch; i++) {
        if(ol_regdmn_vht80_chans->vht80_ch[i] > ch) {
            if((ol_regdmn_vht80_chans->vht80_ch[i] - ch) == 10 ||
               (ol_regdmn_vht80_chans->vht80_ch[i] - ch) == 30) {
                *vht80_ch =  ol_regdmn_vht80_chans->vht80_ch[i];
                return true;
            }
        } else {
            if((ch - ol_regdmn_vht80_chans->vht80_ch[i]) == 10 ||
               (ch - ol_regdmn_vht80_chans->vht80_ch[i]) == 30) {
                *vht80_ch =  ol_regdmn_vht80_chans->vht80_ch[i];
                return true;
            }
        }
    }
    return false;
}

/* Common function to find center frequency for channels with 160 bandwidth i.e. 160 and 80+80 */
static bool ol_regdmn_find_vht160_cmn_chan(struct ol_regdmn_vht160_cmn_chan *ol_regdmn_vht160_cmn_chans,
        u_int16_t ch1, u_int16_t ch2, u_int16_t *pri80_cfreq, u_int16_t *sec80_cfreq)
{
    u_int16_t i, primary_80_match, secondary_80_match;
    primary_80_match = secondary_80_match = 0;

    for( i = 0; i < ol_regdmn_vht160_cmn_chans->n_vht160_cmn_ch; i++) {
        primary_80_match=secondary_80_match=0;
        if(ch1 < ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0]) {   /* finding center freq for band1 */
            if((ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0] - ch1 ) == 10 ||
                    (ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0] - ch1 ) == 30 ) {
                primary_80_match = 1;
            }
        } else if(ch1 > ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0]) {
            if((ch1 - ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0] ) == 10 ||
                    (ch1 - ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0] ) == 30 ) {
                primary_80_match = 1;
            }
        }

        if( primary_80_match == 1 ) {
            if( ch2 < ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1]) {  /* finding center freq for band2 */
                if ((ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1] - ch2 ) == 10 ||
                        (ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1] - ch2 ) == 30) {
                    secondary_80_match=1;
                    break;
                }
            } else if(ch2 > ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1]) {
                if (( ch2 - ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1] ) == 10 ||
                        ( ch2 - ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1] ) == 30) {
                    secondary_80_match=1;
                    break;
                }
            }
        }
    }

    if( primary_80_match == 1 && secondary_80_match == 1) {
        *pri80_cfreq = ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][0];
        *sec80_cfreq = ol_regdmn_vht160_cmn_chans->vht160_cmn_ch[i][1];
        return true ;
    }

    return false;
}


/*
 * Function     : validate_vht80_freq_bounds
 * Description  : Helper function to validate VHT80 bounds for given inputs.
 * Input        : @freq: Center frequency that need to be validated
 *                @freq_low_bound: Frequency lower bound
 *                @freq_high_bound: Frequency higher bound
 */
static int validate_vht80_freq_bounds(u_int16_t freq, u_int16_t freq_low_bound, u_int16_t freq_high_bound)
{
    if (((freq - VHT80_CENTER_EDGE_DIFF) >= freq_low_bound) &&
                ((freq + VHT80_CENTER_EDGE_DIFF) <= freq_high_bound)) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * Function     : validate_vht160_freq_bounds
 * Description  : Helper function to validate VHT160 bounds for given inputs.
 * Input        : @freq: Center requency that need to be validated
 *                @freq_low_bound: Frequency lower bound
 *                @freq_high_bound: Frequency higher bound
 */
static int validate_vht160_freq_bounds(u_int16_t freq, u_int16_t freq_low_bound, u_int16_t freq_high_bound)
{
    if (((freq - VHT160_CENTER_EDGE_DIFF) >= freq_low_bound) &&
                ((freq + VHT160_CENTER_EDGE_DIFF) <= freq_high_bound)) {
        return 1;
    } else {
        return 0;
    }
}


/*
 * Function     : ol_validate_restricted_channel
 * Description  : Helper function to validate whether the primary channel and all its
 *                extension channels for the given mode, lie within the restricted
 *                operating frequency range for the radio.
 * Input        : @scn_handle: pointer to scn object.
 *                @cm: pointer to cmode.
 *                @c: primary channel freq that needs to be valdated.
 *                @vht_ch_freq_seg1: For VHT160/VHT80 :Center frequency of entire
 *                operating span, for VHT80_80: Center frequency of primary 80 MHz.
 *                @vht_ch_freq_seg2: For VHT80_80: Center frequency of secondary 80 MHz.
 */
static int ol_validate_restricted_channel(ol_scn_t scn_handle, const struct cmode *cm,
        u_int16_t c, u_int16_t vht_ch_freq_seg1, u_int16_t vht_ch_freq_seg2)
{
    struct ieee80211com *ic;
    ic = &scn_handle->sc_ic;

    if (!(ic->ic_rch_params.restrict_channel_support)) {
        return 1;
    }

    switch(cm->mode) {
        case REGDMN_MODE_11AC_VHT160:
            /* For VHT160, vht_ch_freq_seg2 represents the centre
             * frequency of entire 160 MHz spectrum. Hence validating
             * only vht_ch_freq_seg2 against restriction is enough.
             */
            if (!validate_vht160_freq_bounds(vht_ch_freq_seg2, ic->ic_rch_params.low_5ghz_chan, ic->ic_rch_params.high_5ghz_chan)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Rejecting entry C: %d vht_ch_freq_seg2: %d for REGDMN_MODE_11AC_VHT160 mode \n", __func__,
                        c, vht_ch_freq_seg2);
                return 0;
            }
            break;

        case REGDMN_MODE_11AC_VHT80_80:
            if (!validate_vht80_freq_bounds(vht_ch_freq_seg1, ic->ic_rch_params.low_5ghz_chan, ic->ic_rch_params.high_5ghz_chan) ||
                    !validate_vht80_freq_bounds(vht_ch_freq_seg2, ic->ic_rch_params.low_5ghz_chan, ic->ic_rch_params.high_5ghz_chan)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s Rejecting entry C: %d vht_ch_freq_seg1: %d vht_ch_freq_seg2: %d for REGDMN_MODE_11AC_VHT80_80 mode \n", __func__,
                        c, vht_ch_freq_seg1, vht_ch_freq_seg2);
                return 0;
            }
            break;

        case REGDMN_MODE_11AC_VHT80:
            if (!validate_vht80_freq_bounds(vht_ch_freq_seg1, ic->ic_rch_params.low_5ghz_chan, ic->ic_rch_params.high_5ghz_chan)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Rejecting entry C: %d vht_ch_freq_seg1: %d for REGDMN_MODE_11AC_VHT80 mode \n", __func__,
                        c, vht_ch_freq_seg1);
                return 0;
            }
            break;

        case REGDMN_MODE_11AC_VHT40PLUS:
        case REGDMN_MODE_11NA_HT40PLUS:
            if (!(c + VHT40_PRIMARY_EDGE_DIFF <= ic->ic_rch_params.high_5ghz_chan) ||
                    !(c - PRIMARY_EDGE_DIFF >= ic->ic_rch_params.low_5ghz_chan)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Rejecting entry for C: %d REGDMN_MODE_11AC_VHT40PLUS mode \n", __func__, c);
                return 0;
            }
            break;

        case REGDMN_MODE_11AC_VHT40MINUS:
        case REGDMN_MODE_11NA_HT40MINUS:
            if (!(c - VHT40_PRIMARY_EDGE_DIFF >= ic->ic_rch_params.low_5ghz_chan) ||
                    !(c + PRIMARY_EDGE_DIFF <= ic->ic_rch_params.high_5ghz_chan)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Rejecting entry for C: %d REGDMN_MODE_11AC_VHT40MINUS mode \n", __func__, c);
                return 0;
            }
            break;

        case REGDMN_MODE_11AC_VHT20:
        case REGDMN_MODE_11NA_HT20:
        case REGDMN_MODE_11A:
            if (!(c + PRIMARY_EDGE_DIFF <= ic->ic_rch_params.high_5ghz_chan) ||
                    !(c - PRIMARY_EDGE_DIFF >= ic->ic_rch_params.low_5ghz_chan)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Rejecting channel: %d for operation \n", __func__, c);
                return 0;
            }
            break;
        default:
            /* Channel restriction feature is not supported for 2.4 GHz
             * So validation for 2.4 GHz related mode will always return 1
             */
           break;
    }


    return 1;
}

static void
populate_icv(struct ieee80211_channel *icv, u_int16_t c, u_int16_t vht_ch_freq_seg1,
        u_int16_t vht_ch_freq_seg2, const REG_DMN_FREQ_BAND *fband, const REG_DMN_FREQ_BAND *fband2, const struct cmode *cm, REG_DOMAIN *rd,
        REG_DOMAIN rd5GHz, HAL_DFS_DOMAIN dfsDomain, ol_scn_t scn_handle, int regdmn, struct ieee80211_channel *chans, int *next)
{

#define CHANNEL_HALF_BW        10
#define CHANNEL_QUARTER_BW    5

    u_int32_t regDmnFlags;
    struct ieee80211com *ic;
    ic = &scn_handle->sc_ic;

    icv->ic_freq = c;
    icv->ic_flags = cm->flags;

    switch (fband->channelBW) {
        case CHANNEL_HALF_BW:
            icv->ic_flags |= IEEE80211_CHAN_HALF;
            break;
        case CHANNEL_QUARTER_BW:
            icv->ic_flags |= IEEE80211_CHAN_QUARTER;
            break;
    }

    icv->ic_maxregpower = fband->powerDfs;
    icv->ic_antennamax = fband->antennaMax;
    regDmnFlags = rd->flags;

    icv->ic_regClassId = fband->regClassId;
    if (fband->usePassScan & rd->pscan)
    {
        /* For WG1_2412_2472, the whole band marked as PSCAN_WWR, but only channel 12-13 need to be passive. */
        if (!(fband->usePassScan & PSCAN_EXT_CHAN) ||
                (icv->ic_freq >= 2467))
        {
            icv->ic_flags |= IEEE80211_CHAN_PASSIVE;
        }
        else if ((fband->usePassScan & PSCAN_MKKA_G) && (rd->pscan & PSCAN_MKKA_G))
        {
            icv->ic_flags |= IEEE80211_CHAN_PASSIVE;
        }
        else
        {
            icv->ic_flags &= ~IEEE80211_CHAN_PASSIVE;
        }
    }
    else
    {
        icv->ic_flags &= ~IEEE80211_CHAN_PASSIVE;
    }
    if (fband->useDfs & rd->dfsMask)
        icv->ic_flagext |= IEEE80211_CHAN_DFS;
    else
        icv->ic_flagext = 0;

    if(fband2 != NULL ) {
        if (fband2->useDfs & rd->dfsMask) {
            icv->ic_flagext |= IEEE80211_CHAN_DFS_CFREQ2;
        }
        else {
            icv->ic_flagext &= ~IEEE80211_CHAN_DFS_CFREQ2;
        }
    }

#if 0 /* Enabling 60 sec startup listen for ETSI */
    /* Don't use 60 sec startup listen for ETSI yet */
    if (fband->useDfs & rd->dfsMask & DFS_ETSI)
        icv->ic_flagext |= IEEE80211_CHAN_DFS_CLEAR;
#endif

    /* Check for ad-hoc allowableness */
    /* To be done: DISALLOW_ADHOC_11A_TURB should allow ad-hoc */
    if (icv->ic_flagext & IEEE80211_CHAN_DFS) {
        icv->ic_flagext |= IEEE80211_CHAN_DISALLOW_ADHOC;
    }
#if 0
    if (icv->regDmnFlags & CHANNEL_NO_HOSTAP) {
        icv->priv_flags |= CHANNEL_NO_HOSTAP;
    }

    if (regDmnFlags & ADHOC_PER_11D) {
        icv->priv_flags |= CHANNEL_PER_11D_ADHOC;
    }
#endif
    if (icv->ic_flags & IEEE80211_CHAN_PASSIVE) {
        /* Allow channel 1-11 as ad-hoc channel even marked as passive */
        if ((icv->ic_freq < 2412) || (icv->ic_freq > 2462)) {
            if (rd5GHz.regDmnEnum == MKK1 || rd5GHz.regDmnEnum == MKK2) {
                u_int32_t regcap;

                regcap = scn_handle->hal_reg_capabilities.regcap2;

                if (!(regcap & (REGDMN_EEPROM_EEREGCAP_EN_KK_U1_EVEN |
                                REGDMN_EEPROM_EEREGCAP_EN_KK_U2 |
                                REGDMN_EEPROM_EEREGCAP_EN_KK_MIDBAND))
                        && isUNII1OddChan(icv->ic_freq)) {
                    /*
                     * There is no RD bit in EEPROM. Unii 1 odd channels
                     * should be active scan for MKK1 and MKK2.
                     */
                    icv->ic_flags &= ~IEEE80211_CHAN_PASSIVE;
                }
                else {
                    icv->ic_flagext |= IEEE80211_CHAN_DISALLOW_ADHOC;
                }
            }
            else {
                icv->ic_flagext |= IEEE80211_CHAN_DISALLOW_ADHOC;
            }
        }
    }
#ifndef ATH_NO_5G_SUPPORT
    if (cm->mode & (REGDMN_MODE_TURBO | REGDMN_MODE_11A_TURBO)) {
        if( regDmnFlags & DISALLOW_ADHOC_11A_TURB) {
            icv->ic_flagext |= IEEE80211_CHAN_DISALLOW_ADHOC;
        }
    }
#endif
    else if (cm->mode & (REGDMN_MODE_11A | REGDMN_MODE_11NA_HT20 |
                REGDMN_MODE_11NA_HT40PLUS | REGDMN_MODE_11NA_HT40MINUS)) {
        if( regDmnFlags & (ADHOC_NO_11A | DISALLOW_ADHOC_11A)) {
            icv->ic_flagext |= IEEE80211_CHAN_DISALLOW_ADHOC;
        }
    }

#ifdef ATH_IBSS_DFS_CHANNEL_SUPPORT
    /* EV 83788, 83790 support 11A adhoc in ETSI domain. Other
     * domain will remain as their original settings for now since there
     * is no requirement.
     * This will open all 11A adhoc in ETSI, no matter DFS/non-DFS
     */
    if (dfsDomain == DFS_ETSI_DOMAIN) {
        icv->ic_flagext &= ~IEEE80211_CHAN_DISALLOW_ADHOC;
    }
#endif

    if (regdmn == OVERRIDE_RD && ol_regdmn_duplicate_channel(icv, chans, *next+1))
        return;
    icv->ic_ieee = ol_ath_mhz2ieee(ic, icv->ic_freq, icv->ic_flags);
    if(vht_ch_freq_seg1) {
        icv->ic_vhtop_ch_freq_seg1 = ol_ath_mhz2ieee(ic, vht_ch_freq_seg1, icv->ic_flags);
    }
    else {
        icv->ic_vhtop_ch_freq_seg1 = 0;
    }
    if(vht_ch_freq_seg2) {
        icv->ic_vhtop_ch_freq_seg2 = ol_ath_mhz2ieee(ic, vht_ch_freq_seg2, icv->ic_flags);
    }
    else {
        icv->ic_vhtop_ch_freq_seg2 = 0;
    }
    OS_MEMCPY(&chans[(*next)++], icv, sizeof(struct ieee80211_channel));

#undef CHANNEL_HALF_BW
#undef CHANNEL_QUARTER_BW
}

bool __ahdecl
ol_regdmn_init_channels(struct ol_regdmn *ol_regdmn_handle,
              struct ieee80211_channel *chans, u_int maxchans, u_int *nchans,
              u_int8_t *regclassids, u_int maxregids, u_int *nregids,
              REGDMN_CTRY_CODE cc, u_int32_t modeSelect,
              bool enableOutdoor, bool enableExtendedChannels,
              bool block_dfs_enable)
{
#define CHANNEL_HALF_BW        10
#define CHANNEL_QUARTER_BW    5
    u_int modesAvail;
    u_int16_t maxChan=7000;
    const COUNTRY_CODE_TO_ENUM_RD *country=AH_NULL;
    REG_DOMAIN rd5GHz, rd2GHz;
    const struct cmode *cm;
    int next=0,b;
    u_int8_t ctl;
    int is_quarterchan_cap, is_halfchan_cap, is_49ghz_cap;
    HAL_DFS_DOMAIN dfsDomain=0;
    int regdmn;
    u_int16_t chanSep;
    ol_scn_t scn_handle;
    struct ieee80211com *ic;
    u_int32_t ch144, ch144_eppr_ovrd;

    struct ol_ath_softc_net80211 *scn = NULL;
    scn_handle = ol_regdmn_handle->scn_handle;
    ic = &scn_handle->sc_ic;
    sec_channel_count = 0;
    ch144_eppr_ovrd = 0;

    scn = OL_ATH_SOFTC_NET80211(ic);
    /*
     * We now have enough state to validate any country code
     * passed in by the caller.
     */
    if (!isCountryCodeValid(ol_regdmn_handle, cc)) {
        /* NB: Atheros silently ignores invalid country codes */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: invalid country code %d\n",
                __func__, cc);
        return false;
    }

    /*
     * Validate the EEPROM setting and setup defaults
     */
    if (!isEepromValid(ol_regdmn_handle)) {
        /*
         * Don't return any channels if the EEPROM has an
         * invalid regulatory domain/country code setting.
         */
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: invalid EEPROM contents\n",__func__);
        return false;
    }

    ol_regdmn_handle->ol_regdmn_countryCode = getDefaultCountry(ol_regdmn_handle);

    if (ol_regdmn_handle->ol_regdmn_countryCode == CTRY_DEFAULT) {
        /*
         * XXX - TODO: Switch based on Japan country code
         * to new reg domain if valid japan card
         */
        ol_regdmn_handle->ol_regdmn_countryCode = cc & COUNTRY_CODE_MASK;

        if ((ol_regdmn_handle->ol_regdmn_countryCode == CTRY_DEFAULT) &&
                (getEepromRD(ol_regdmn_handle) == CTRY_DEFAULT)) {
                /* Set to DEBUG_REG_DMN for debug or set to CTRY_UNITED_STATES for testing */
                ol_regdmn_handle->ol_regdmn_countryCode = CTRY_UNITED_STATES;
        }
    }

#ifdef REGDMN_SUPPORT_11D
    if(ol_regdmn_handle->ol_regdmn_countryCode == CTRY_DEFAULT)
    {
        regdmn =getEepromRD(ol_regdmn_handle) & ~COUNTRY_ERD_FLAG;
        country = AH_NULL;
    }
    else {
#endif
        /* Get pointers to the country element and the reg domain elements */
        country = findCountry(ol_regdmn_handle->ol_regdmn_countryCode, getEepromRD(ol_regdmn_handle));

        if (country == AH_NULL) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Country is NULL!!!!, cc= %d\n",
                ol_regdmn_handle->ol_regdmn_countryCode);
            return false;
        } else {
            regdmn = country->regDmnEnum;
#ifdef REGDMN_SUPPORT_11D
            if (((getEepromRD(ol_regdmn_handle) & WORLD_SKU_MASK) == WORLD_SKU_PREFIX) && (cc == CTRY_UNITED_STATES)) {
                if(!isWwrSKU_NoMidband(ol_regdmn_handle) && isFCCMidbandSupported(ol_regdmn_handle))
                    regdmn = FCC3_FCCA;
                else
                    regdmn = FCC1_FCCA;
            }
#endif
        }
#ifdef REGDMN_SUPPORT_11D
    }
#endif

#ifndef ATH_NO_5G_SUPPORT
    if (!getWmRD(ol_regdmn_handle, regdmn, ~IEEE80211_CHAN_2GHZ, &rd5GHz)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: couldn't find unitary 5GHz reg domain for country %u\n",
             __func__, ol_regdmn_handle->ol_regdmn_countryCode);
        return false;
    }
#endif
    if (!getWmRD(ol_regdmn_handle, regdmn, IEEE80211_CHAN_2GHZ, &rd2GHz)) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: couldn't find unitary 2GHz reg domain for country %u\n",
             __func__, ol_regdmn_handle->ol_regdmn_countryCode);
        return false;
    }

    if (rd5GHz.dfsMask & DFS_FCC3)
        dfsDomain = DFS_FCC_DOMAIN;
    if (rd5GHz.dfsMask & DFS_MKK4)
        dfsDomain = DFS_MKK4_DOMAIN;
    if (rd5GHz.dfsMask & DFS_ETSI)
        dfsDomain = DFS_ETSI_DOMAIN;
    if (dfsDomain != ol_regdmn_handle->ol_regdmn_dfsDomain) {
        ol_regdmn_handle->ol_regdmn_dfsDomain = dfsDomain;
    }
    if(country == AH_NULL) {
        modesAvail = ol_regdmn_getWirelessModes(ol_regdmn_handle);
    }
    else {
        modesAvail = ol_regdmn_getwmodesnreg(ol_regdmn_handle, country, &rd5GHz);

        if (cc == CTRY_DEBUG) {
            if (modesAvail & REGDMN_MODE_11N_MASK) {
                modeSelect &= REGDMN_MODE_11N_MASK;
            }
        }
		/* To skip 5GHZ channel when cc is NULL1_WORLD */
		if (cc == NULL1_WORLD) {
            modeSelect &= ~(REGDMN_MODE_11A|REGDMN_MODE_TURBO|REGDMN_MODE_108A|REGDMN_MODE_11A_HALF_RATE|REGDMN_MODE_11A_QUARTER_RATE
							|REGDMN_MODE_11NA_HT20|REGDMN_MODE_11NA_HT40PLUS|REGDMN_MODE_11NA_HT40MINUS);
        }

        if (!enableOutdoor)
            maxChan = country->outdoorChanStart;
    }
    next = 0;

    is_halfchan_cap = scn_handle->hal_reg_capabilities.regcap1 & REGDMN_CAP1_CHAN_HALF_RATE;
    is_quarterchan_cap = scn_handle->hal_reg_capabilities.regcap1 & REGDMN_CAP1_CHAN_QUARTER_RATE;
    is_49ghz_cap = scn_handle->hal_reg_capabilities.regcap1 & REGDMN_CAP1_CHAN_HAL49GHZ;

#if ICHAN_WAR_SYNCH
//    lock may need on the operartion of IEEE channel list
//    AH_PRIVATE(ah)->ah_ichan_set = true;
//    spin_lock(&AH_PRIVATE(ah)->ah_ichan_lock);
#endif
    for (cm = modes; cm < &modes[N(modes)]; cm++) {
        u_int16_t c, c_hi, c_lo,temp_chans[30],numchans=0,i,j;
        u_int64_t *channelBM=AH_NULL;
        REG_DOMAIN *rd=AH_NULL;
        const REG_DMN_FREQ_BAND *fband=AH_NULL,*freqs;
        int8_t low_adj=0, hi_adj=0;
        u_int16_t vht_ch_freq_seg1, vht_ch_freq_seg2;
        u_int16_t pri80_cfreq, sec80_cfreq;

        vht_ch_freq_seg1 = vht_ch_freq_seg2 = 0;
        pri80_cfreq = sec80_cfreq = 0;

        if ((cm->mode & modeSelect) == 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: skip mode 0x%x flags 0x%x\n",
                 __func__, cm->mode, cm->flags);
            continue;
        }
        if ((cm->mode & modesAvail) == 0) {
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s: !avail mode 0x%x (0x%x) flags 0x%x\n",
                 __func__, modesAvail, cm->mode, cm->flags);
            continue;
        }
        if (!ol_get_channel_edges(ol_regdmn_handle, cm->flags, &c_lo, &c_hi)) {
            /* channel not supported by hardware, skip it */
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: channels 0x%x not supported by hardware\n",
                 __func__,cm->flags);
            continue;
        }

        switch (cm->mode) {
#ifndef ATH_NO_5G_SUPPORT
        case REGDMN_MODE_TURBO:
            rd = &rd5GHz;
            channelBM = rd->chan11a_turbo;
            freqs = &regDmn5GhzTurboFreq[0];
            ctl = rd->conformance_test_limit | CTL_TURBO;
            break;
        case REGDMN_MODE_11A:
        case REGDMN_MODE_11NA_HT20:
        case REGDMN_MODE_11NA_HT40PLUS:
        case REGDMN_MODE_11NA_HT40MINUS:
        case REGDMN_MODE_11AC_VHT20:
        case REGDMN_MODE_11AC_VHT40PLUS:
        case REGDMN_MODE_11AC_VHT40MINUS:
        case REGDMN_MODE_11AC_VHT80:
        case REGDMN_MODE_11AC_VHT160:
        case REGDMN_MODE_11AC_VHT80_80:
            rd = &rd5GHz;
            channelBM = rd->chan11a;
            freqs = &regDmn5GhzFreq[0];
            ctl = rd->conformance_test_limit;
            break;
#endif
        case REGDMN_MODE_11B:
            rd = &rd2GHz;
            channelBM = rd->chan11b;
            freqs = &regDmn2GhzFreq[0];
            ctl = rd->conformance_test_limit | CTL_11B;
            break;
        case REGDMN_MODE_11G:
        case REGDMN_MODE_11NG_HT20:
        case REGDMN_MODE_11NG_HT40PLUS:
        case REGDMN_MODE_11NG_HT40MINUS:
            rd = &rd2GHz;
            channelBM = rd->chan11g;
            freqs = &regDmn2Ghz11gFreq[0];
            ctl = rd->conformance_test_limit | CTL_11G;
            break;
        case REGDMN_MODE_11G_TURBO:
            rd = &rd2GHz;
            channelBM = rd->chan11g_turbo;
            freqs = &regDmn2Ghz11gTurboFreq[0];
            ctl = rd->conformance_test_limit | CTL_108G;
            break;
#ifndef ATH_NO_5G_SUPPORT
        case REGDMN_MODE_11A_TURBO:
            rd = &rd5GHz;
            channelBM = rd->chan11a_dyn_turbo;
            freqs = &regDmn5GhzTurboFreq[0];
            ctl = rd->conformance_test_limit | CTL_108G;
            break;
#endif
        default:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unkonwn HAL mode 0x%x\n",
                    __func__, cm->mode);
            continue;
        }
        if (isChanBitMaskZero(channelBM))
            continue;

        if ((cm->mode == REGDMN_MODE_11NA_HT40PLUS) ||
            (cm->mode == REGDMN_MODE_11NG_HT40PLUS) ||
            (cm->mode == REGDMN_MODE_11AC_VHT40PLUS)) {
                hi_adj = -20;
        }

        if ((cm->mode == REGDMN_MODE_11NA_HT40MINUS) ||
            (cm->mode == REGDMN_MODE_11NG_HT40MINUS) ||
	    (cm->mode == REGDMN_MODE_11AC_VHT40MINUS)) {
                low_adj = 20;
        }
        if ((cm->mode == REGDMN_MODE_11AC_VHT80_80) && (rd == &rd5GHz))
        {
            ol_regdmn_init_vht80_80_chan(&vht80_80_chans);

            if (regdmn != OVERRIDE_RD) {
                // Find 80 M channels
                for (b=0;b<64*BMLEN; b++) {
                    if (IS_BIT_SET(b,channelBM)) {
                        fband = &freqs[b];
                        for (c=fband->lowChannel + 30;
                                ((c <= (fband->highChannel - 30)) &&
                                 (c >= (fband->lowChannel + 30)));
                                c += 80) {
                            if((c <= (fband->highChannel - 30)) &&
                                    (c >= (fband->lowChannel + 30)))
                                temp_chans[numchans++]=c;
                        }
                    }
                }
                for (i=0; i<numchans; i++) {
                    for (j=i+1; j<numchans; j++) {
                        if (temp_chans[j] > temp_chans[i]) {
                            if ( temp_chans[j] - temp_chans[i] > 80 ) {
                                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans,temp_chans[i],temp_chans[j]);
                                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans,temp_chans[j],temp_chans[i]);
                            }
                        } else if (temp_chans[j] < temp_chans[i]) {
                            if ( temp_chans[i] - temp_chans[j] > 80 ) {
                                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans,temp_chans[j],temp_chans[i]);
                                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans,temp_chans[i],temp_chans[j]);
                            }
                        }
                    }
                }
            }
            else {
                /* for override domain, hardcode the 5g 80_80Mhz band */
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5210,5530);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5530,5210);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5210,5690);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5690,5210);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5210,5775);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5775,5210);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5290,5530);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5530,5290);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5290,5690);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5690,5290);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5290,5775);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5775,5290);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5530,5690);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5690,5530);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5530,5775);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5775,5530);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5690,5775);
                ol_regdmn_add_vht160_cmn_chan(&vht80_80_chans, 5775,5690);
            }
        } else if ((cm->mode == REGDMN_MODE_11AC_VHT160) && (rd == &rd5GHz)) {

            ol_regdmn_init_vht80_80_chan(&vht160_chans);
            if (regdmn != OVERRIDE_RD) {
                // Find 160 M channels
                for (b=0;b<64*BMLEN; b++) {
                    if (IS_BIT_SET(b,channelBM)) {
                        fband = &freqs[b];
                        for (c=fband->lowChannel + 30;
                                ((c <= (fband->highChannel - 30)) &&
                                 (c >= (fband->lowChannel + 30)));
                                c += 80) {
                            if((c <= (fband->highChannel - 30)) &&
                                    (c >= (fband->lowChannel + 30)))
                                temp_chans[numchans++]=c;
                        }
                    }
                }
                for (i=0; i<numchans; i++) {
                    for (j=i+1; j<numchans; j++) {
                        if ((temp_chans[j] - temp_chans[i] == 80) || (temp_chans[i] - temp_chans[j] == 80)) {
                            if((temp_chans[j] == 5610 && temp_chans[i] == 5690) || (temp_chans[j] == 5690 && temp_chans[i] == 5610))
                                    continue;
                            ol_regdmn_add_vht160_cmn_chan(&vht160_chans,temp_chans[i],temp_chans[j]);
                            ol_regdmn_add_vht160_cmn_chan(&vht160_chans,temp_chans[j],temp_chans[i]);
                        }
                    }
                }
            }
            else {
                /* for override domain, harcode the 5g 160Mhz band */
                ol_regdmn_add_vht160_cmn_chan(&vht160_chans, 5210,5290);
                ol_regdmn_add_vht160_cmn_chan(&vht160_chans, 5530,5610);
                ol_regdmn_add_vht160_cmn_chan(&vht160_chans, 5290,5210);
                ol_regdmn_add_vht160_cmn_chan(&vht160_chans, 5610,5530);
            }
        }
        // Walk through the 5G band to find 80 Mhz channel
        else  if ((cm->mode == REGDMN_MODE_11AC_VHT80) && (rd == &rd5GHz))
        {
            ol_regdmn_init_vht80_chan(&vht80_chans);

            if (regdmn != OVERRIDE_RD) {
                // Find 80 M channels
                for (b=0;b<64*BMLEN; b++) {
                    if (IS_BIT_SET(b,channelBM)) {
                        fband = &freqs[b];
                        for (c=fband->lowChannel + 30;
                                ((c <= (fband->highChannel - 30)) &&
                                 (c >= (fband->lowChannel + 30)));
                                c += 80) {
                            if((c <= (fband->highChannel - 30)) &&
                                    (c >= (fband->lowChannel + 30)))
                                ol_regdmn_add_vht80_chan(&vht80_chans, c);
                        }
                    }
                }
            } else {
                /* for override domain, harcode the 5g 80Mhz band */
                ol_regdmn_add_vht80_chan(&vht80_chans, 5210);
                ol_regdmn_add_vht80_chan(&vht80_chans, 5290);
                ol_regdmn_add_vht80_chan(&vht80_chans, 5530);
                ol_regdmn_add_vht80_chan(&vht80_chans, 5690);
                ol_regdmn_add_vht80_chan(&vht80_chans, 5775);
            }
        }

        if(rd == &rd2GHz) {
            ol_regdmn_handle->ol_regdmn_ctl_2G = ctl;
        }

#ifndef ATH_NO_5G_SUPPORT
        if (rd == &rd5GHz ) {
           ol_regdmn_handle->ol_regdmn_ctl_5G = ctl;
        }
#endif

        for (b=0;b<64*BMLEN; b++) {
            if (IS_BIT_SET(b,channelBM)) {
                fband = &freqs[b];

#ifndef ATH_NO_5G_SUPPORT
                if (block_dfs_enable)
                {
                    if (fband->useDfs != NO_DFS)
                        continue;
                }
                /*
                 * MKK capability check. U1 ODD, U1 EVEN, U2, and MIDBAND bits are checked here.
                 * Don't add the band to channel list if the corresponding bit is not set.
                 */
                if ((cm->flags & IEEE80211_CHAN_5GHZ) && (rd5GHz.regDmnEnum == MKK1 || rd5GHz.regDmnEnum == MKK2)) {
                    int i, skipband=0;
                    u_int32_t regcap;

                    for (i = 0; i < N(j_bandcheck); i++) {
                        if (j_bandcheck[i].freqbandbit == b) {
                            regcap = scn_handle->hal_reg_capabilities.regcap2;

                            if ((j_bandcheck[i].eepromflagtocheck & regcap) == 0) {
                                skipband = 1;
                            }
                            break;
                        }
                    }
                    if (skipband) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Skipping %d freq band.\n",
                                __func__, j_bandcheck[i].freqbandbit);
                        continue;
                    }
                }
#endif

                ath_add_regclassid(regclassids, maxregids,
                                   nregids, fband->regClassId);

                if ((rd == &rd5GHz) && (fband->lowChannel < 5180) &&
                    (!is_49ghz_cap) && (regdmn != OVERRIDE_RD))
                    continue;

                if (((IS_HT40_MODE(cm->mode)) || (IS_VHT40_MODE(cm->mode))) && (rd == &rd5GHz)) {
                    /* For 5G HT40 mode, channel seperation should be 40. */
                    chanSep = 40;

                    /*
                     * For all 4.9G Hz and Unii1 odd channels, HT40 is not allowed.
                     * Except for CTRY_DEBUG.
                     */
                    if ((fband->lowChannel < 5180) && (cc != CTRY_DEBUG) && (regdmn != OVERRIDE_RD)) {
                        continue;
                    }

                    /*
                     * This is mainly for F1_5280_5320, where 5280 is not a HT40_PLUS channel.
                     * The way we generate HT40 channels is assuming the freq band starts from
                     * a HT40_PLUS channel. Shift the low_adj by 20 to make it starts from 5300.
                     */
                    if ((fband->lowChannel == 5280) || (fband->lowChannel == 4920)) {
                        low_adj += 20;
                    }
                }
                else {
                    chanSep = fband->channelSep;

                    if (cm->mode == REGDMN_MODE_11NA_HT20 || cm->mode == REGDMN_MODE_11AC_VHT20) {
                        /*
                         * For all 4.9G Hz and Unii1 odd channels, HT20 is not allowed either.
                         * Except for CTRY_DEBUG.
                         */
                        if ((fband->lowChannel < 5180) && (cc != CTRY_DEBUG) && (regdmn != OVERRIDE_RD)) {
                            continue;
                        }
                    }
                }

                for (c=fband->lowChannel + low_adj;
                     ((c <= (fband->highChannel + hi_adj)) &&
                      (c >= (fband->lowChannel + low_adj)));
                     c += chanSep) {

                    struct ieee80211_channel icv;

                    if (!(c_lo <= c && c <= c_hi)) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_DEBUG"%s: c %u out of range [%u..%u]\n",
                             __func__, c, c_lo, c_hi);
                        continue;
                    }
                    if ((fband->channelBW ==
                            CHANNEL_HALF_BW) &&
                        !is_halfchan_cap) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Skipping %u half rate channel\n",
                                __func__, c);
                        continue;
                    }

                    if ((fband->channelBW ==
                        CHANNEL_QUARTER_BW) &&
                        !is_quarterchan_cap) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Skipping %u quarter rate channel\n",
                                __func__, c);
                        continue;
                    }

                    if (((c+fband->channelSep)/2) > (maxChan+HALF_MAXCHANBW)) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: c %u > maxChan %u\n",
                             __func__, c, maxChan);
                        continue;
                    }
                    if (next >= maxchans){
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: too many channels for channel table\n",
                             __func__);
                        goto done;
                    }
                    if ((fband->usePassScan & IS_ECM_CHAN) &&
                        !enableExtendedChannels && (c >= 2467)) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Skipping ecm channel\n");
                        continue;
                    }
                    if ((rd->flags & NO_HOSTAP) &&
                        (scn_handle->sc_ic.ic_opmode == IEEE80211_M_HOSTAP)) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Skipping HOSTAP channel\n");
                        continue;
                    }
                    // This code makes sense for only the AP side. The following if's deal specifically
                    // with Owl since it does not support radar detection on extension channels.
                    // For STA Mode, the AP takes care of switching channels when radar detection
                    // happens. Also, for SWAP mode, Apple does not allow DFS channels, and so allowing
                    // HT40 operation on these channels is OK.
                    if (IS_HT40_MODE(cm->mode) &&
                        !(getEepromRegExtBits(ol_regdmn_handle,REG_EXT_FCC_DFS_HT40)) &&
                        (fband->useDfs) && (rd->conformance_test_limit != MKK)) {
                        /*
                         * Only MKK CTL checks REG_EXT_JAPAN_DFS_HT40 for DFS HT40 support.
                         * All other CTLs should check REG_EXT_FCC_DFS_HT40
                         */
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Skipping HT40 channel (en_fcc_dfs_ht40 = 0)\n");
                        continue;
                    }
                    if (IS_HT40_MODE(cm->mode) &&
                        !(getEepromRegExtBits(ol_regdmn_handle, REG_EXT_JAPAN_NONDFS_HT40)) &&
                        !(fband->useDfs) && (rd->conformance_test_limit == MKK)) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Skipping HT40 channel (en_jap_ht40 = 0)\n");
                        continue;
                    }
                    if (IS_HT40_MODE(cm->mode) &&
                        !(getEepromRegExtBits(ol_regdmn_handle, REG_EXT_JAPAN_DFS_HT40)) &&
                        (fband->useDfs) && (rd->conformance_test_limit == MKK) ) {
                        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Skipping HT40 channel (en_jap_dfs_ht40 = 0)\n");
                        continue;
                    }
                    if(rd == &rd5GHz)
                    {
                        /*
                            This is for enabling channel 144 for FCC3 and FCC6 according to
                            RD extension bit 5 and software 144 setting
                            RD extension bit 5 == 0. Ch. 144 is not certified. No Tx allowed in
                            Ch. 144 even Ch. 144 is extension channel.

                        */

                        /* Adding secondary 80 channels in an array in the first traversal when mode is REGDMN_MODE_11AC_VHT80.
                           This array will be used to find second center frequency in case of mode REGDMN_MODE_11AC_VHT80_80 */
                        if(cm->mode & REGDMN_MODE_11AC_VHT80) {
                            sec_80_chans[sec_channel_count].sec_chan = c;
                            sec_80_chans[sec_channel_count++].fband = fband;
                        }
                        if((b == F1_5500_5720) || (b == F2_5660_5720) || (b == F3_5660_5720)) {

                            ch144 = ol_regdmn_handle->ol_regdmn_ch144;
                            ch144_eppr_ovrd = ol_regdmn_handle->ol_regdmn_ch144_eppovrd;

                            if(((c == 5660) || (c == 5680) || (c == 5700) || (c == 5720)) && (cm->mode & REGDMN_MODE_11AC_VHT80)
                                         && ((!ch144_eppr_ovrd)?(!getEepromRegExtBits(ol_regdmn_handle, REG_EXT_FCC_CH_144)):0)) {

                                sec_channel_count--;
                            }

                            if(((c == 5660) || (c == 5680)) && (cm->mode & (REGDMN_MODE_11AC_VHT80 | REGDMN_MODE_11AC_VHT80_80))
                                    && ((!ch144_eppr_ovrd)?(!getEepromRegExtBits(ol_regdmn_handle, REG_EXT_FCC_CH_144)):0)) {
                                /*
                                    Skipping 132, 136 VHT80/VHT80+80 channel when RD extension bit5 == 0
                                */
                                continue;
                            }

                            if((c == 5700) && (cm->mode & (REGDMN_MODE_11NA_HT40PLUS | REGDMN_MODE_11AC_VHT40PLUS |
                                REGDMN_MODE_11AC_VHT80 | REGDMN_MODE_11AC_VHT160 | REGDMN_MODE_11AC_VHT80_80)) &&
				(((!ch144_eppr_ovrd) ? (!getEepromRegExtBits(ol_regdmn_handle, REG_EXT_FCC_CH_144)):0) |
				!(ch144 & REGDMN_CH144_SEC20_ALLOWED))) {
                                /*
                                    Skipping 140 VHT40 and VHT80 channel when RD bit 5 == 0 or
                                    Ch. 144 sec20 is not allowed
                                */
                                continue;
                            }

                            if(c == 5720 && (((!ch144_eppr_ovrd)? (!getEepromRegExtBits(ol_regdmn_handle, REG_EXT_FCC_CH_144)):0) |
                                !(ch144 & REGDMN_CH144_PRI20_ALLOWED))) {
                                /*
                                    Skipping all 144 channel. when RD bit 5 == 0 or Ch. 144 pri20
                                    is not allowed
                                */
                                continue;
                            }
                        }
                    }

                    OS_MEMZERO(&icv, sizeof(icv));
                    if(cm->mode == REGDMN_MODE_11AC_VHT80_80) {

                        if ((fband->lowChannel < 5180) && (cc != CTRY_DEBUG) && (regdmn != OVERRIDE_RD)) {
                            continue;
                        }
                        for(i = 0 ;i < sec_channel_count; i++) {
                            /* To find valid secondary 80 MHz center frequencies, we use a list of 20 MHz channels
                             * which can form the secondary 80. However, to avoid multiple entries for the same
                             * <primary chan,pri80 center,sec80 center> combination we consider only the first
                             * 20 MHz channel in the sec80 segment. The center of this 20 MHz channel will be at
                             * an offset of 30 MHz behind the sec80 center.
                             */
                            if(ol_regdmn_find_vht160_cmn_chan(&vht80_80_chans, c,sec_80_chans[i].sec_chan, &vht_ch_freq_seg1, &vht_ch_freq_seg2) &&
                               (sec_80_chans[i].sec_chan == (vht_ch_freq_seg2 - 30))) {
                                if (ol_validate_restricted_channel(scn_handle, cm, c, vht_ch_freq_seg1, vht_ch_freq_seg2)) {
                                    if((ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) && \
                                           (vht_ch_freq_seg1 > vht_ch_freq_seg2)) {
                                        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,IEEE80211_MSG_DEBUG,
                                        "EMI WAR rejecting fc1 > fc2 Combination cfreq1:%u, cfreq2:%u in case of VHT80+80\n",
                                                                                          vht_ch_freq_seg1,vht_ch_freq_seg2);
                                        continue;
                                    } else if((ic->ic_emiwar_80p80 == EMIWAR_80P80_BANDEDGE) && \
                                            (vht_ch_freq_seg1 == 5775 && vht_ch_freq_seg2 == 5210)) {
                                        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,IEEE80211_MSG_DEBUG,
                                        "EMI WAR rejecting BandEdge Combination cfreq1:5775, cfreq2:5210 in case of VHT80+80 \n");
                                        continue;
                                    }
                                    populate_icv(&icv, c, vht_ch_freq_seg1, vht_ch_freq_seg2, fband, sec_80_chans[i].fband, cm,
                                            rd, rd5GHz, dfsDomain, scn_handle, regdmn, chans, &next);
                                }
                            }
                        }
                    } else if(cm->mode == REGDMN_MODE_11AC_VHT160) {
                        if ((fband->lowChannel < 5180) && (cc != CTRY_DEBUG) && (regdmn != OVERRIDE_RD)) {
                            continue;
                        }

                        for(i = 0 ;i < sec_channel_count; i++) {
                            /* To find valid secondary 80 MHz center frequencies, we use a list of 20 MHz channels
                             * which can form the secondary 80. However, to avoid multiple entries for the same
                             * <primary chan,pri80 center,sec80 center> combination we consider only the first
                             * 20 MHz channel in the sec80 segment. The center of this 20 MHz channel will be at
                             * an offset of 30 MHz behind the sec80 center.
                             */
                            if(ol_regdmn_find_vht160_cmn_chan(&vht160_chans, c,sec_80_chans[i].sec_chan, &pri80_cfreq, &sec80_cfreq)) {
                                if(((pri80_cfreq - sec80_cfreq == 80) || (sec80_cfreq - pri80_cfreq == 80)) && (sec_80_chans[i].sec_chan == (sec80_cfreq - 30))) {
                                    vht_ch_freq_seg1 = pri80_cfreq;
                                    vht_ch_freq_seg2 = (pri80_cfreq + sec80_cfreq)/2;

                                    if (ol_validate_restricted_channel(scn_handle, cm, c, vht_ch_freq_seg1, vht_ch_freq_seg2)) {
                                        populate_icv(&icv, c, vht_ch_freq_seg1, vht_ch_freq_seg2, fband, sec_80_chans[i].fband,
                                                cm, rd, rd5GHz,dfsDomain, scn_handle, regdmn, chans, &next);
                                    }
                                }
                            }
                        }
                    } else if(cm->mode == REGDMN_MODE_11AC_VHT80) {
                        /*
                         * For all 4.9G, VHT80 is not allowed.
                         * Except for CTRY_DEBUG.
                         */
                        if ((fband->lowChannel < 5180) && (cc != CTRY_DEBUG) && (regdmn != OVERRIDE_RD)) {
                            continue;
                        }

                        if(!ol_regdmn_find_vht80_chan(&vht80_chans, c, &vht_ch_freq_seg1)) {
                            if (regdmn != OVERRIDE_RD){
                                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"Skipping VHT80 channel %d\n", c);
                            }
                            continue;
                        }
                        vht_ch_freq_seg2 = 0;
                        if (ol_validate_restricted_channel(scn_handle, cm, c, vht_ch_freq_seg1, vht_ch_freq_seg2)) {
                            populate_icv(&icv, c, vht_ch_freq_seg1, vht_ch_freq_seg2, fband, 0,  cm, rd, rd5GHz, dfsDomain, scn_handle, regdmn, chans, &next);
                        }
                    }

                    else {
                        vht_ch_freq_seg1 = vht_ch_freq_seg2 = 0;
                        if (ol_validate_restricted_channel(scn_handle, cm, c, vht_ch_freq_seg1, vht_ch_freq_seg2)) {
                            populate_icv(&icv, c, vht_ch_freq_seg1, vht_ch_freq_seg2, fband, 0,  cm, rd, rd5GHz, dfsDomain, scn_handle, regdmn, chans, &next);
                        }
                    }

                }
                    /* Restore normal low_adj value. */
                    if (IS_HT40_MODE(cm->mode) || IS_VHT40_MODE(cm->mode)) {
                        if (fband->lowChannel == 5280 || fband->lowChannel == 4920) {
                            low_adj -= 20;
                        }
                    }
                }
            }
        }
done:    if (next != 0) {

        /*
         * Keep a private copy of the channel list so we can
         * constrain future requests to only these channels
         */
        ath_hal_sort(chans, next, sizeof(struct ieee80211_channel), chansort);

    }
    *nchans = next;

    ieee80211_set_nchannels(ic, next);

    /* save for later query */
    ol_regdmn_handle->ol_regdmn_currentRDInUse = regdmn;
    ol_regdmn_handle->ol_regdmn_currentRD5G = rd5GHz.regDmnEnum;
    ol_regdmn_handle->ol_regdmn_currentRD2G = rd2GHz.regDmnEnum;

    if(country == AH_NULL) {
        ol_regdmn_handle->ol_regdmn_iso[0] = 0;
        ol_regdmn_handle->ol_regdmn_iso[1] = 0;
    }
    else {
        ol_regdmn_handle->ol_regdmn_iso[0] = country->isoName[0];
        ol_regdmn_handle->ol_regdmn_iso[1] = country->isoName[1];
    }

#if ICHAN_WAR_SYNCH
//    lock may need on the operartion of IEEE channel list
//    AH_PRIVATE(ah)->ah_ichan_set = false;
//    spin_unlock(&AH_PRIVATE(ah)->ah_ichan_lock);
#endif

    return (next != 0);
#undef CHANNEL_HALF_BW
#undef CHANNEL_QUARTER_BW
}

/*
 * Insertion sort.
 */
#define ath_hal_swap(_a, _b, _size) {            \
    u_int8_t *s = _b;                    \
    int i = _size;                       \
    do {                                 \
        u_int8_t tmp = *_a;              \
        *_a++ = *s;                      \
        *s++ = tmp;                      \
    } while (--i);                       \
    _a -= _size;                         \
}

static void
ath_hal_sort(void *a, u_int32_t n, u_int32_t size, ath_hal_cmp_t *cmp)
{
    u_int8_t *aa = a;
    u_int8_t *ai, *t;

    for (ai = aa+size; --n >= 1; ai += size)
        for (t = ai; t > aa; t -= size) {
            u_int8_t *u = t - size;
            if (cmp(u, t) <= 0)
                break;
            ath_hal_swap(u, t, size);
        }
}

static bool
ol_regdmn_duplicate_channel(struct ieee80211_channel *chan,
                            struct ieee80211_channel *list, int size) {
    u_int16_t i;

    for (i=0; i<size; i++) {
        if (chan->ic_freq == list[i].ic_freq &&
            chan->ic_flags == list[i].ic_flags &&
            chan->ic_flagext == list[i].ic_flagext)
            return true;
    }

    return false;
}

REGDMN_CTRY_CODE __ahdecl ol_regdmn_findCountryCodeByRegDomain(REGDMN_REG_DOMAIN regdmn)
{
    int i;

    for (i = 0; i < ol_regdmn_Rdt.allCountriesCt; i++) {
        if (ol_regdmn_Rdt.allCountries[i].regDmnEnum == regdmn)
            return (ol_regdmn_Rdt.allCountries[i].countryCode);
    }
    return (0);        /* Not found */
}

void __ahdecl ol_regdmn_getCurrentCountry(struct ol_regdmn* ol_regdmn_handle, IEEE80211_COUNTRY_ENTRY* ctry)
{


    u_int16_t rd = getEepromRD(ol_regdmn_handle);

    ctry->isMultidomain = false;
    if(!(rd & COUNTRY_ERD_FLAG)) {
        ctry->isMultidomain = isWwrSKU(ol_regdmn_handle);
    }

    ctry->countryCode = ol_regdmn_handle->ol_regdmn_countryCode;
    ctry->regDmnEnum = ol_regdmn_handle->ol_regdmn_current_rd;
    ctry->regDmn5G = ol_regdmn_handle->ol_regdmn_currentRD5G;
    ctry->regDmn2G = ol_regdmn_handle->ol_regdmn_currentRD2G;
    ctry->iso[0] = ol_regdmn_handle->ol_regdmn_iso[0];
    ctry->iso[1] = ol_regdmn_handle->ol_regdmn_iso[1];
}

#undef N

void
ol_80211_channel_setup(struct ieee80211com *ic,
                           enum ieee80211_clist_cmd cmd,
                           struct ieee80211_channel *chans, int nchan,
                           const u_int8_t *regclassids, u_int nregclass,
                           int countryCode)
{

    /*
     * The DFS/NOL management is now done via ic_dfs_clist_update(),
     * rather than via the channel setup API.
     */
    if ((cmd == CLIST_DFS_UPDATE) || (cmd == CLIST_NOL_UPDATE)) {
        qdf_print("%s: cmd=%d, should not have gotten here!\n",
          __func__,
          cmd);
    }

    if ((countryCode == CTRY_DEFAULT) || (cmd == CLIST_NEW_COUNTRY)) {
        /*
         * channel is ready.
         */
    }
    else {
        /*
         * TBD
         * Logic AND the country channel and domain channels.
         */
    }

    /*
     * Copy regclass ids
     */
    ieee80211_set_regclassids(ic, regclassids, nregclass);
}

static int
ol_ath_set_country(struct ieee80211com *ic,
                         char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_regdmn *ol_regdmn_handle;
    struct ieee80211_channel *chans;
    int nchan;
    u_int8_t regclassids[ATH_REGCLASSIDS_MAX];
    u_int nregclass = 0;
    u_int wMode;
    u_int netBand;
    int outdoor = ath_outdoor;
    int indoor = ath_indoor;
    u_int i;
    u_int16_t orig_cc = 0;
    REGDMN_REG_DOMAIN curRd;

    ol_regdmn_handle = scn->ol_regdmn_handle;

    /* backup original cc, if set country code failed, restore */
    orig_cc = ol_regdmn_handle->ol_regdmn_countryCode;
    if(!isoName || !isoName[0] || !isoName[1]) {
        if (cc)
            ol_regdmn_handle->ol_regdmn_countryCode = cc;
        else
            ol_regdmn_handle->ol_regdmn_countryCode = CTRY_DEFAULT;
    } else {
        curRd = ol_regdmn_handle->ol_regdmn_current_rd &~ WORLDWIDE_ROAMING_FLAG;
        ol_regdmn_handle->ol_regdmn_countryCode = ol_regdmn_findCountryCodeForCurrentRD((u_int8_t *)isoName, curRd);
        //ol_regdmn_handle->ol_regdmn_countryCode = ol_regdmn_findCountryCode((u_int8_t *)isoName);

        /* Map the ISO name ' ', 'I', 'O' */
        if (isoName[2] == 'O') {
            outdoor = AH_TRUE;
            indoor  = AH_FALSE;
            ath_table = 0;
        }
        else if (isoName[2] == 'I') {
            indoor  = AH_TRUE;
            outdoor = AH_FALSE;
            ath_table = 0;
        }
        else if ((isoName[2] == ' ') || (isoName[2] == 0)) {
            outdoor = AH_FALSE;
            indoor  = AH_FALSE;
            ath_table = 0;
        }
        else if ((isoName[2] >= '1') && (isoName[2] <= '9')) {
            outdoor = AH_FALSE;
            indoor  = AH_FALSE;
            ath_table = isoName[2] - '0';
        }
        else
            return -EINVAL;
    }

    wMode = ic->ic_reg_parm.wModeSelect;
    if (!(wMode & REGDMN_MODE_11A)) {
        wMode &= ~(REGDMN_MODE_TURBO|REGDMN_MODE_108A|REGDMN_MODE_11A_HALF_RATE);
    }
    if (!(wMode & REGDMN_MODE_11G)) {
        wMode &= ~(REGDMN_MODE_108G);
    }
    netBand = ic->ic_reg_parm.netBand;
    if (!(netBand & REGDMN_MODE_11A)) {
        netBand &= ~(REGDMN_MODE_TURBO|REGDMN_MODE_108A|REGDMN_MODE_11A_HALF_RATE);
    }
    if (!(netBand & REGDMN_MODE_11G)) {
        netBand &= ~(REGDMN_MODE_108G);
    }
    wMode &= netBand;

    chans = ic->ic_channels;

    if (chans == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to allocate channel table\n", __func__);
        return -ENOMEM;
    }

    if (!ol_regdmn_init_channels(ol_regdmn_handle, chans, IEEE80211_CHAN_MAX, (u_int *)&nchan,
                               regclassids, ATH_REGCLASSIDS_MAX, &nregclass,
                               ol_regdmn_handle->ol_regdmn_countryCode, wMode, outdoor,
                               ol_regdmn_handle->ol_regdmn_xchanmode,
                               scn->sc_is_blockdfs_set)) {
        /* set country code failed, restore original cc */
        ol_regdmn_handle->ol_regdmn_countryCode = orig_cc;
        return -EINVAL;
    }

    for (i=0; i<nchan; i++) {
        chans[i].ic_maxpower = scn->max_tx_power;
        chans[i].ic_minpower = scn->min_tx_power;
    }

    ol_80211_channel_setup(ic, cmd,
                           chans, nchan, regclassids, nregclass,
                           ol_regdmn_handle->ol_regdmn_countryCode);

#ifdef OL_ATH_DUMP_RD_SPECIFIC_CHANNELS
	ol_ath_dump_rd_specific_channels(ic, ol_regdmn_handle);
#endif

    ol_ath_pdev_set_regdomain(scn, ol_regdmn_handle);

    return 0;
}

static void
ol_ath_get_currentCountry(struct ieee80211com *ic, IEEE80211_COUNTRY_ENTRY *ctry)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_regdmn *ol_regdmn_handle;

    ol_regdmn_handle = scn->ol_regdmn_handle;

    ol_regdmn_getCurrentCountry(ol_regdmn_handle, ctry);

    /* If HAL not specific yet, since it is band dependent, use the one we passed in.*/
    if (ctry->countryCode == CTRY_DEFAULT) {
        ctry->iso[0] = 0;
        ctry->iso[1] = 0;
    }
    else if (ctry->iso[0] && ctry->iso[1]) {
        if (ath_outdoor)
            ctry->iso[2] = 'O';
        else if (ath_indoor)
            ctry->iso[2] = 'I';
        else if (ath_table)
            ctry->iso[2] = ath_table;
        else
            ctry->iso[2] = ' ';
    }
    return;
}

static int
ol_ath_set_regdomain(struct ieee80211com *ic, int regdomain)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_regdmn *ol_regdmn_handle;
    int ret;
    IEEE80211_REG_PARAMETERS *reg_parm;
    int orig_regdomain = 0;
    reg_parm = &ic->ic_reg_parm;
    ol_regdmn_handle = scn->ol_regdmn_handle;
    /* backup original regdomain, if set regdomain failed, restore */
    orig_regdomain = ol_regdmn_handle->ol_regdmn_current_rd;
    if (ol_regdmn_set_regdomain(ol_regdmn_handle, regdomain))
            ret = !ol_regdmn_getchannels(ol_regdmn_handle, CTRY_DEFAULT, AH_FALSE, AH_TRUE, reg_parm);
        else
            ret = AH_FALSE;

    if (ret == AH_TRUE)
        return 0;
    else{
        /* set regdomain failed, restore */
        ol_regdmn_handle->ol_regdmn_current_rd = orig_regdomain;
        return -EIO;
    }
}

static int
ol_ath_get_dfsdomain(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_regdmn *ol_regdmn_handle;

    ol_regdmn_handle = scn->ol_regdmn_handle;

    return ol_regdmn_handle->ol_regdmn_dfsDomain;
}

static u_int16_t
ol_ath_find_countrycode(struct ieee80211com *ic, char* isoName)
{
    /* TBD */
    return 0;
}

/* Regdomain Initialization functions */
int
ol_regdmn_attach(ol_scn_t scn_handle)
{
    struct ol_regdmn *ol_regdmn_handle;
    struct ieee80211com *ic = &scn_handle->sc_ic;


    ic->ic_get_currentCountry = ol_ath_get_currentCountry;
    ic->ic_set_country = ol_ath_set_country;
    ic->ic_set_regdomain = ol_ath_set_regdomain;
    ic->ic_find_countrycode = ol_ath_find_countrycode;
    ic->ic_get_dfsdomain = ol_ath_get_dfsdomain;

    ol_regdmn_handle = (struct ol_regdmn *)OS_MALLOC(scn_handle->sc_osdev, sizeof(struct ol_regdmn), GFP_ATOMIC);
    if (ol_regdmn_handle == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "allocation of ol regdmn handle failed %d \n",sizeof(struct ol_regdmn));
        return 1;
    }
    OS_MEMZERO(ol_regdmn_handle, sizeof(struct ol_regdmn));
    ol_regdmn_handle->scn_handle = scn_handle;
    ol_regdmn_handle->osdev = scn_handle->sc_osdev;

    scn_handle->ol_regdmn_handle = ol_regdmn_handle;

    ol_regdmn_handle->ol_regdmn_current_rd = 0; /* Current regulatory domain */
    ol_regdmn_handle->ol_regdmn_current_rd_ext = PEREGRINE_RDEXT_DEFAULT;    /* Regulatory domain Extension reg from EEPROM*/
    ol_regdmn_handle->ol_regdmn_countryCode = CTRY_DEFAULT;     /* current country code */

    return 0;
}

bool ol_regdmn_set_ch144(struct ol_regdmn *ol_regdmn_handle, u_int ch144)
{
    ol_regdmn_handle->ol_regdmn_ch144 = ch144;
    return TRUE;
}

bool ol_regdmn_set_ch144_eppovrd(struct ol_regdmn *ol_regdmn_handle, u_int ch144)
{
    if (ch144 >= 0){
        ol_regdmn_handle->ol_regdmn_ch144_eppovrd = (ch144 ? 1 : 0); /*user input shall act as bool*/
        return TRUE;
    } else
        return FALSE;
}

bool ol_regdmn_get_ch144(struct ol_regdmn *ol_regdmn_handle, u_int *ch144)
{
    *ch144 = ol_regdmn_handle->ol_regdmn_ch144;
    return TRUE;
}

/**
* @brief        Checks if 160 MHz flag is set in wireless_modes
*
* @param hal_cap:   pointer to HAL_REG_CAPABILITIES
*
* @return       true if 160 MHz flag is set, false otherwise.
*/
bool ol_regdmn_get_160mhz_support(TARGET_HAL_REG_CAPABILITIES *hal_cap)
{
    return ((hal_cap->wireless_modes & REGDMN_MODE_11AC_VHT160) != 0);
}

/**
* @brief        Checks if 80+80 MHz flag is set in wireless_modes
*
* @param hal_cap:   pointer to HAL_REG_CAPABILITIES
*
* @return       true if 80+80 MHz flag is set, false otherwise.
*/
bool ol_regdmn_get_80p80mhz_support(TARGET_HAL_REG_CAPABILITIES *hal_cap)
{
    return ((hal_cap->wireless_modes & REGDMN_MODE_11AC_VHT80_80) != 0);
}
