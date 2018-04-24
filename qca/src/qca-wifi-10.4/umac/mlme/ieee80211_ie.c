/*
 * Copyright (c) 2011, 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 *
 *  all the IE parsing/processing routines.
 */
#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include "ieee80211_mlme_priv.h"
#include "ol_if_athvar.h"

#define	IEEE80211_ADDSHORT(frm, v) 	do {frm[0] = (v) & 0xff; frm[1] = (v) >> 8;	frm += 2;} while (0)
#define	IEEE80211_ADDSELECTOR(frm, sel) do {OS_MEMCPY(frm, sel, 4); frm += 4;} while (0)
#define IEEE80211_SM(_v, _f)    (((_v) << _f##_S) & _f)
#define RX_MCS_SINGLE_STREAM_BYTE_OFFSET 0
#define RX_MCS_DUAL_STREAM_BYTE_OFFSET 1
#define RX_MCS_ALL_NSTREAM_RATES 0xff

void
ieee80211_savenie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie, u_int ielen);
void ieee80211_saveie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie);
u_int8_t *
ieee80211_add_vht_wide_bw_switch(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, int is_vendor_ie);

/*
 * Add a supported rates element id to a frame.
 */
u_int8_t *
ieee80211_add_rates(u_int8_t *frm, const struct ieee80211_rateset *rs)
{
    int nrates;

    *frm++ = IEEE80211_ELEMID_RATES;
    nrates = rs->rs_nrates;
    if (nrates > IEEE80211_RATE_SIZE)
        nrates = IEEE80211_RATE_SIZE;
    *frm++ = nrates;
    OS_MEMCPY(frm, rs->rs_rates, nrates);
    return frm + nrates;
}

/*
 * Add an extended supported rates element id to a frame.
 */
u_int8_t *
ieee80211_add_xrates(u_int8_t *frm, const struct ieee80211_rateset *rs)
{
    /*
     * Add an extended supported rates element if operating in 11g mode.
     */
    if (rs->rs_nrates > IEEE80211_RATE_SIZE) {
        int nrates = rs->rs_nrates - IEEE80211_RATE_SIZE;
        *frm++ = IEEE80211_ELEMID_XRATES;
        *frm++ = nrates;
        OS_MEMCPY(frm, rs->rs_rates + IEEE80211_RATE_SIZE, nrates);
        frm += nrates;
    }
    return frm;
}

/*
 * Add an ssid elemet to a frame.
 */
u_int8_t *
ieee80211_add_ssid(u_int8_t *frm, const u_int8_t *ssid, u_int len)
{
    *frm++ = IEEE80211_ELEMID_SSID;
    *frm++ = len;
    OS_MEMCPY(frm, ssid, len);
    return frm + len;
}

/*
 * Add an erp element to a frame.
 */
u_int8_t *
ieee80211_add_erp(u_int8_t *frm, struct ieee80211com *ic)
{
    u_int8_t erp;

    *frm++ = IEEE80211_ELEMID_ERP;
    *frm++ = 1;
    erp = 0;
    if (ic->ic_nonerpsta != 0 )
        erp |= IEEE80211_ERP_NON_ERP_PRESENT;
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        erp |= IEEE80211_ERP_USE_PROTECTION;
    if (ic->ic_flags & IEEE80211_F_USEBARKER)
        erp |= IEEE80211_ERP_LONG_PREAMBLE;
    *frm++ = erp;
    return frm;
}

/*
 * Add a country information element to a frame.
 */
u_int8_t *
ieee80211_add_country(u_int8_t *frm, struct ieee80211vap *vap)
{
    u_int16_t chanflags;
    struct ieee80211com *ic = vap->iv_ic;

    /* add country code */
    if(IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        chanflags = IEEE80211_CHAN_2GHZ;
    else
        chanflags = IEEE80211_CHAN_5GHZ;

    ic->ic_country_iso[0] = ic->ic_country.iso[0];
    ic->ic_country_iso[1] = ic->ic_country.iso[1];
    ic->ic_country_iso[2] = ic->ic_country.iso[2];

    if (chanflags != vap->iv_country_ie_chanflags)
        ieee80211_build_countryie(vap);

    if (vap->iv_country_ie_data.country_len) {
    	OS_MEMCPY(frm, (u_int8_t *)&vap->iv_country_ie_data,
	    	vap->iv_country_ie_data.country_len + 2);
	    frm +=  vap->iv_country_ie_data.country_len + 2;
    }

    return frm;
}

#if ATH_SUPPORT_IBSS_DFS
/*
* Add a IBSS DFS element into a frame
*/
u_int8_t *
ieee80211_add_ibss_dfs(u_int8_t *frm, struct ieee80211vap *vap)
{

    OS_MEMCPY(frm, (u_int8_t *)&vap->iv_ibssdfs_ie_data,
              vap->iv_ibssdfs_ie_data.len + sizeof(struct ieee80211_ie_header));
    frm += vap->iv_ibssdfs_ie_data.len + sizeof(struct ieee80211_ie_header);

    return frm;
}

u_int8_t *
ieee80211_add_ibss_csa(u_int8_t *frm, struct ieee80211vap *vap)
{

    OS_MEMCPY(frm, (u_int8_t *)&vap->iv_channelswitch_ie_data,
              vap->iv_channelswitch_ie_data.len + sizeof(struct ieee80211_ie_header));
    frm += vap->iv_channelswitch_ie_data.len + sizeof(struct ieee80211_ie_header);

    return frm;
}
#endif /* ATH_SUPPORT_IBSS_DFS */

u_int8_t *
ieee80211_setup_wpa_ie(struct ieee80211vap *vap, u_int8_t *ie)
{
    static const u_int8_t oui[4] = { WPA_OUI_BYTES, WPA_OUI_TYPE };
    static const u_int8_t cipher_suite[IEEE80211_CIPHER_MAX][4] = {
        { WPA_OUI_BYTES, WPA_CSE_WEP40 },    /* NB: 40-bit */
        { WPA_OUI_BYTES, WPA_CSE_TKIP },
        { 0x00, 0x00, 0x00, 0x00 },        /* XXX WRAP */
        { WPA_OUI_BYTES, WPA_CSE_CCMP },
        { 0x00, 0x00, 0x00, 0x00 },        /* XXX CKIP */
        { WPA_OUI_BYTES, WPA_CSE_NULL },
    };
    static const u_int8_t wep104_suite[4] =
        { WPA_OUI_BYTES, WPA_CSE_WEP104 };
    static const u_int8_t key_mgt_unspec[4] =
        { WPA_OUI_BYTES, AKM_SUITE_TYPE_IEEE8021X };
    static const u_int8_t key_mgt_psk[4] =
        { WPA_OUI_BYTES, AKM_SUITE_TYPE_PSK };
    static const u_int8_t key_mgt_cckm[4] =
        { CCKM_OUI_BYTES, CCKM_ASE_UNSPEC };
    const struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    ieee80211_cipher_type mcastcipher;
    u_int8_t *frm = ie;
    u_int8_t *selcnt;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;                /* length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));        /* WPA OUI */
    frm += sizeof(oui);
    IEEE80211_ADDSHORT(frm, WPA_VERSION);

    /* XXX filter out CKIP */

    /* multicast cipher */
    mcastcipher = ieee80211_get_current_mcastcipher(vap);
    if (mcastcipher == IEEE80211_CIPHER_WEP &&
        rsn->rsn_mcastkeylen >= 13)
        IEEE80211_ADDSELECTOR(frm, wep104_suite);
    else{
            if(mcastcipher < IEEE80211_CIPHER_NONE)
                    IEEE80211_ADDSELECTOR(frm, cipher_suite[mcastcipher]);
    }

    /* unicast cipher list */
    selcnt = frm;
    IEEE80211_ADDSHORT(frm, 0);			/* selector count */
/* do not use CCMP unicast cipher in WPA mode */
#if IEEE80211_USE_WPA_CCMP
    if (RSN_CIPHER_IS_CCMP128(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_CCM]);
    }
    if (RSN_CIPHER_IS_CCMP256(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_CCM_256]);
    }
    if (RSN_CIPHER_IS_GCMP128(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_GCM]);
    }
    if (RSN_CIPHER_IS_GCMP256(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_GCM_256]);
    }
#endif
    if (RSN_CIPHER_IS_TKIP(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_TKIP]);
    }

    /* authenticator selector list */
    selcnt = frm;
	IEEE80211_ADDSHORT(frm, 0);			/* selector count */
    if (RSN_AUTH_IS_CCKM(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, key_mgt_cckm);
    } else {
    if (rsn->rsn_keymgmtset & WPA_ASE_8021X_UNSPEC) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, key_mgt_unspec);
    }
    if (rsn->rsn_keymgmtset & WPA_ASE_8021X_PSK) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, key_mgt_psk);
    }
    }

    /* optional capabilities */
    if (rsn->rsn_caps != 0 && rsn->rsn_caps != RSN_CAP_PREAUTH)
        IEEE80211_ADDSHORT(frm, rsn->rsn_caps);

    /* calculate element length */
    ie[1] = frm - ie - 2;
    KASSERT(ie[1]+2 <= sizeof(struct ieee80211_ie_wpa),
            ("WPA IE too big, %u > %zu", ie[1]+2, sizeof(struct ieee80211_ie_wpa)));
    return frm;
}

u_int8_t *
ieee80211_setup_rsn_ie(struct ieee80211vap *vap, u_int8_t *ie)
{
    static const u_int8_t cipher_suite[][4] = {
        { RSN_OUI_BYTES, RSN_CSE_WEP40 },    /* NB: 40-bit */
        { RSN_OUI_BYTES, RSN_CSE_TKIP },
        { RSN_OUI_BYTES, RSN_CSE_WRAP },
        { RSN_OUI_BYTES, RSN_CSE_CCMP },
        { RSN_OUI_BYTES, RSN_CSE_CCMP },   /* WAPI */
        { CCKM_OUI_BYTES, RSN_CSE_NULL },  /* XXX CKIP */
        { RSN_OUI_BYTES, RSN_CSE_AES_CMAC }, /* AES_CMAC */
        { RSN_OUI_BYTES, RSN_CSE_CCMP_256 },   /* CCMP 256 */
        { RSN_OUI_BYTES, RSN_CSE_BIP_CMAC_256 }, /* AES_CMAC 256*/
        { RSN_OUI_BYTES, RSN_CSE_GCMP_128 },
        { RSN_OUI_BYTES, RSN_CSE_GCMP_256 },   /* GCMP 256 */
        { RSN_OUI_BYTES, RSN_CSE_BIP_GMAC_128 }, /* AES_GMAC */
        { RSN_OUI_BYTES, RSN_CSE_BIP_GMAC_256 }, /* AES_GMAC 256*/
        { RSN_OUI_BYTES, RSN_CSE_NULL },
    };
    static const u_int8_t wep104_suite[4] =
        { RSN_OUI_BYTES, RSN_CSE_WEP104 };
    static const u_int8_t key_mgt_unspec[4] =
        { RSN_OUI_BYTES, AKM_SUITE_TYPE_IEEE8021X };
    static const u_int8_t key_mgt_psk[4] =
        { RSN_OUI_BYTES, AKM_SUITE_TYPE_PSK };
    static const u_int8_t key_mgt_sha256_1x[4] =
        { RSN_OUI_BYTES, AKM_SUITE_TYPE_SHA256_IEEE8021X };
    static const u_int8_t key_mgt_sha256_psk[4] =
        { RSN_OUI_BYTES, AKM_SUITE_TYPE_SHA256_PSK };
    static const u_int8_t key_mgt_cckm[4] =
        { CCKM_OUI_BYTES, CCKM_ASE_UNSPEC };
    const struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    ieee80211_cipher_type mcastcipher;
    u_int8_t *frm = ie;
    u_int8_t *selcnt, pmkidFilled=0;
    int i;

    *frm++ = IEEE80211_ELEMID_RSN;
    *frm++ = 0;                /* length filled in below */
    IEEE80211_ADDSHORT(frm, RSN_VERSION);

    /* XXX filter out CKIP */

    /* multicast cipher */
    mcastcipher = ieee80211_get_current_mcastcipher(vap);
    if (mcastcipher == IEEE80211_CIPHER_WEP &&
        rsn->rsn_mcastkeylen >= 13) {
        IEEE80211_ADDSELECTOR(frm, wep104_suite);
    } else {
        IEEE80211_ADDSELECTOR(frm, cipher_suite[mcastcipher]);
    }

    /* unicast cipher list */
    selcnt = frm;
    IEEE80211_ADDSHORT(frm, 0);			/* selector count */
    if (RSN_CIPHER_IS_CCMP128(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_CCM]);
    }
   if (RSN_CIPHER_IS_CCMP256(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_CCM_256]);
    }
    if (RSN_CIPHER_IS_GCMP128(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_GCM]);
    }
    if (RSN_CIPHER_IS_GCMP256(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_GCM_256]);
    }

    if (RSN_CIPHER_IS_TKIP(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_TKIP]);
    }

    /* authenticator selector list */
    selcnt = frm;
	IEEE80211_ADDSHORT(frm, 0);			/* selector count */
    if (RSN_AUTH_IS_CCKM(rsn)) {
        selcnt[0]++;
        IEEE80211_ADDSELECTOR(frm, key_mgt_cckm);
    } else {
        if (rsn->rsn_keymgmtset & RSN_ASE_8021X_UNSPEC) {
            selcnt[0]++;
            IEEE80211_ADDSELECTOR(frm, key_mgt_unspec);
        }
        if (rsn->rsn_keymgmtset & RSN_ASE_8021X_PSK) {
            selcnt[0]++;
            IEEE80211_ADDSELECTOR(frm, key_mgt_psk);
        }
        if (rsn->rsn_keymgmtset & RSN_ASE_SHA256_IEEE8021X) {
            selcnt[0]++;
            IEEE80211_ADDSELECTOR(frm, key_mgt_sha256_1x);
        }
        if (rsn->rsn_keymgmtset & RSN_ASE_SHA256_PSK) {
            selcnt[0]++;
            IEEE80211_ADDSELECTOR(frm, key_mgt_sha256_psk);
        }
    }

    /* capabilities */
    IEEE80211_ADDSHORT(frm, rsn->rsn_caps);

    /* PMKID */
    if (vap->iv_opmode == IEEE80211_M_STA && vap->iv_pmkid_count > 0) {
        struct ieee80211_node *ni = vap->iv_bss; /* bss node */
        /* Find and include the PMKID for target AP*/
        for (i = 0; i < vap->iv_pmkid_count; i++) {
            if (!OS_MEMCMP( vap->iv_pmkid_list[i].bssid, ni->ni_bssid, IEEE80211_ADDR_LEN)) {
                IEEE80211_ADDSHORT(frm, 1);
                OS_MEMCPY(frm, vap->iv_pmkid_list[i].pmkid, IEEE80211_PMKID_LEN);
                frm += IEEE80211_PMKID_LEN;
                pmkidFilled = 1;
                break;
            }
        }
    }

    /* mcast/group mgmt cipher set (optional 802.11w) */
    if ((vap->iv_opmode == IEEE80211_M_HOSTAP)  &&  (rsn->rsn_caps & RSN_CAP_MFP_ENABLED)) {
        if (!pmkidFilled) {
            /* PMKID is not filled. so put zero for PMKID count */
            IEEE80211_ADDSHORT(frm, 0);
        }
        if(RSN_CIPHER_IS_CMAC(rsn))
            IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_CMAC]);
        else if(RSN_CIPHER_IS_CMAC256(rsn))
            IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_CMAC_256]);
        else if(RSN_CIPHER_IS_GMAC(rsn))
            IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_GMAC]);
        else if(RSN_CIPHER_IS_GMAC256(rsn))
            IEEE80211_ADDSELECTOR(frm, cipher_suite[IEEE80211_CIPHER_AES_GMAC_256]);
    }

    /* calculate element length */
    ie[1] = frm - ie - 2;
    KASSERT(ie[1]+2 <= sizeof(struct ieee80211_ie_wpa),
            ("RSN IE too big, %u > %zu", ie[1]+2, sizeof(struct ieee80211_ie_wpa)));
    return frm;
}
int
ieee80211_get_rxstreams(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    u_int8_t rx_streams = 0;
    if(ic->ic_is_mode_offload(ic) && vap->iv_nss!=0){
        rx_streams = MIN(vap->iv_nss,ieee80211_getstreams(ic, ic->ic_rx_chainmask));
    }else{
        rx_streams = ieee80211_getstreams(ic, ic->ic_rx_chainmask);
    }
#if ATH_SUPPORT_WAPI
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
       (RSN_CIPHER_IS_SMS4(&vap->iv_rsn))) {
        if (rx_streams > ic->ic_num_wapi_rx_maxchains)
            rx_streams = ic->ic_num_wapi_rx_maxchains;
    }
#endif
    return rx_streams;
}

int
ieee80211_get_txstreams(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    u_int8_t tx_streams = 0;
    if(ic->ic_is_mode_offload(ic) && vap->iv_nss!=0){
        tx_streams = MIN(vap->iv_nss,ieee80211_getstreams(ic, ic->ic_tx_chainmask));
    }else{
        tx_streams = ieee80211_getstreams(ic, ic->ic_tx_chainmask);
    }
#if ATH_SUPPORT_WAPI
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
       (RSN_CIPHER_IS_SMS4(&vap->iv_rsn))) {
        if (tx_streams > ic->ic_num_wapi_tx_maxchains)
            tx_streams = ic->ic_num_wapi_tx_maxchains;
    }
#endif
    return tx_streams;
}

/* add IE for WAPI in mgmt frames */
#if ATH_SUPPORT_WAPI
u_int8_t *
ieee80211_setup_wapi_ie(struct ieee80211vap *vap, u_int8_t *ie)
{
#define	ADDSHORT(frm, v) do {frm[0] = (v) & 0xff;frm[1] = (v) >> 8;frm += 2;} while (0)
#define	ADDSELECTOR(frm, sel) do {OS_MEMCPY(frm, sel, 4); frm += 4;} while (0)
#define	WAPI_OUI_BYTES		0x00, 0x14, 0x72

	static const u_int8_t cipher_suite[4] =
		{ WAPI_OUI_BYTES, WAPI_CSE_WPI_SMS4};	/* SMS4 128 bits */
	static const u_int8_t key_mgt_unspec[4] =
		{ WAPI_OUI_BYTES, WAPI_ASE_WAI_UNSPEC };
	static const u_int8_t key_mgt_psk[4] =
		{ WAPI_OUI_BYTES, WAPI_ASE_WAI_PSK };
	const struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
	u_int8_t *frm = ie;
	u_int8_t *selcnt;
	*frm++ = IEEE80211_ELEMID_WAPI;
	*frm++ = 0;				/* length filled in below */
	ADDSHORT(frm, WAPI_VERSION);

	/* authenticator selector list */
	selcnt = frm;
	ADDSHORT(frm, 0);			/* selector count */

	if (rsn->rsn_keymgmtset & WAPI_ASE_WAI_UNSPEC) {
		selcnt[0]++;
		ADDSELECTOR(frm, key_mgt_unspec);
	}
	if (rsn->rsn_keymgmtset & WAPI_ASE_WAI_PSK) {
		selcnt[0]++;
		ADDSELECTOR(frm, key_mgt_psk);
	}

	/* unicast cipher list */
	selcnt = frm;
	ADDSHORT(frm, 0);			/* selector count */

	if (RSN_HAS_UCAST_CIPHER(rsn, IEEE80211_CIPHER_WAPI)) {
		selcnt[0]++;
		ADDSELECTOR(frm, cipher_suite);
	}

	/* multicast cipher */
	ADDSELECTOR(frm, cipher_suite);

	/* optional capabilities */
	ADDSHORT(frm, rsn->rsn_caps);
	/* XXX PMKID */

    /* BKID count, only in ASSOC/REASSOC REQ frames from STA to AP*/
    if (vap->iv_opmode == IEEE80211_M_STA) {
        ADDSHORT(frm, 0);
    }

	/* calculate element length */
	ie[1] = frm - ie - 2;
	KASSERT(ie[1]+2 <= sizeof(struct ieee80211_ie_wpa),
		("RSN IE too big, %u > %u",
		ie[1]+2, sizeof(struct ieee80211_ie_wpa)));
	return frm;
#undef ADDSELECTOR
#undef ADDSHORT
#undef WAPI_OUI_BYTES
}
#endif /*ATH_SUPPORT_WAPI*/

/*
 * Add a WME Info element to a frame.
 */
u_int8_t *
ieee80211_add_wmeinfo(u_int8_t *frm, struct ieee80211_node *ni,
                      u_int8_t wme_subtype, u_int8_t *wme_info, u_int8_t info_len)
{
    static const u_int8_t oui[4] = { WME_OUI_BYTES, WME_OUI_TYPE };
    struct ieee80211_ie_wme *ie = (struct ieee80211_ie_wme *) frm;
    struct ieee80211_wme_state *wme = &ni->ni_ic->ic_wme;
    struct ieee80211vap *vap = ni->ni_vap;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;                             /* length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));       /* WME OUI */
    frm += sizeof(oui);
    *frm++ = wme_subtype;          /* OUI subtype */
    switch (wme_subtype) {
    case WME_INFO_OUI_SUBTYPE:
        *frm++ = WME_VERSION;                   /* protocol version */
        /* QoS Info field depends on operating mode */
        ie->wme_info = 0;
        switch (vap->iv_opmode) {
        case IEEE80211_M_HOSTAP:
            *frm = wme->wme_bssChanParams.cap_info & WME_QOSINFO_COUNT;
            if (IEEE80211_VAP_IS_UAPSD_ENABLED(vap)) {
                *frm |= WME_CAPINFO_UAPSD_EN;
            }
            frm++;
            break;
        case IEEE80211_M_STA:
            /* Set the U-APSD flags */
            if (ieee80211_vap_wme_is_set(vap) && (ni->ni_ext_caps & IEEE80211_NODE_C_UAPSD)) {
                *frm |= vap->iv_uapsd;
            }
            frm++;
            break;
        default:
            *frm++ = 0;
        }
        break;
    case WME_TSPEC_OUI_SUBTYPE:
        *frm++ = WME_TSPEC_OUI_VERSION;        /* protocol version */
        OS_MEMCPY(frm, wme_info, info_len);
        frm += info_len;
        break;
    default:
        break;
    }

    ie->wme_len = (u_int8_t)(frm - &ie->wme_oui[0]);

    return frm;
}

/*
 * Add a WME Parameter element to a frame.
 */
u_int8_t *
ieee80211_add_wme_param(u_int8_t *frm, struct ieee80211_wme_state *wme,
                        int uapsd_enable)
{
    static const u_int8_t oui[4] = { WME_OUI_BYTES, WME_OUI_TYPE };
    struct ieee80211_wme_param *ie = (struct ieee80211_wme_param *) frm;
    int i;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;				/* length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));		/* WME OUI */
    frm += sizeof(oui);
    *frm++ = WME_PARAM_OUI_SUBTYPE;		/* OUI subtype */
    *frm++ = WME_VERSION;			/* protocol version */

    ie->param_qosInfo = 0;
    *frm = wme->wme_bssChanParams.cap_info & WME_QOSINFO_COUNT;
    if (uapsd_enable) {
        *frm |= WME_CAPINFO_UAPSD_EN;
    }
    frm++;
    *frm++ = 0;                             /* reserved field */
    for (i = 0; i < WME_NUM_AC; i++) {
        const struct wmeParams *ac =
            &wme->wme_bssChanParams.cap_wmeParams[i];
        *frm++ = IEEE80211_SM(i, WME_PARAM_ACI)
            | IEEE80211_SM(ac->wmep_acm, WME_PARAM_ACM)
            | IEEE80211_SM(ac->wmep_aifsn, WME_PARAM_AIFSN)
            ;
        *frm++ = IEEE80211_SM(ac->wmep_logcwmax, WME_PARAM_LOGCWMAX)
            | IEEE80211_SM(ac->wmep_logcwmin, WME_PARAM_LOGCWMIN)
            ;
        IEEE80211_ADDSHORT(frm, ac->wmep_txopLimit);
    }

    ie->param_len = frm - &ie->param_oui[0];

    return frm;
}

/*
 * Add an Atheros Advanaced Capability element to a frame
 */
u_int8_t *
ieee80211_add_athAdvCap(u_int8_t *frm, u_int8_t capability, u_int16_t defaultKey)
{
    static const u_int8_t oui[6] = {(ATH_OUI & 0xff), ((ATH_OUI >>8) & 0xff),
                                    ((ATH_OUI >> 16) & 0xff), ATH_OUI_TYPE, ATH_OUI_SUBTYPE, ATH_OUI_VERSION};
    struct ieee80211_ie_athAdvCap *ie = (struct ieee80211_ie_athAdvCap *) frm;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;				/* Length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));		/* Atheros OUI, type, subtype, and version for adv capabilities */
    frm += sizeof(oui);
    *frm++ = capability;

    /* Setup default key index in little endian byte order */
    *frm++ = (defaultKey & 0xff);
    *frm++ = ((defaultKey >> 8)& 0xff);
    ie->athAdvCap_len = frm - &ie->athAdvCap_oui[0];

    return frm;
}

/*
 *  Add a QCA bandwidth-NSS Mapping information element to a frame
 */
u_int8_t *
ieee80211_add_bw_nss_maping(u_int8_t *frm, struct ieee80211_bwnss_map *bw_nss_mapping)
{
    static const u_int8_t oui[6] = {(ATH_OUI & 0xff), ((ATH_OUI >>8) & 0xff),
                                   ((ATH_OUI >> 16) & 0xff),ATH_OUI_BW_NSS_MAP_TYPE,
                                       ATH_OUI_BW_NSS_MAP_SUBTYPE, ATH_OUI_BW_NSS_VERSION};
    struct ieee80211_bwnss_mapping *ie = (struct ieee80211_bwnss_mapping *) frm;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0x00;                            /* Length filled in below */
    OS_MEMCPY(frm, oui, IEEE80211_N(oui));    /* QCA OUI, type, sub-type, version, bandwidth NSS mapping Vendor specific IE  */
    frm += IEEE80211_N(oui);
    *frm++ = IEEE80211_BW_NSS_ADV_160(bw_nss_mapping->bw_nss_160); /* XXX: Add higher BW map if and when required */

    ie->bnm_len = (frm - &ie->bnm_oui[0]);
    return frm;
}

u_int8_t* add_chan_switch_ie(u_int8_t *frm, struct ieee80211_channel *next_ch, u_int8_t tbtt_cnt)
{
    struct ieee80211_channelswitch_ie *csaie = (struct ieee80211_channelswitch_ie*)frm;
    int csaielen = sizeof(struct ieee80211_channelswitch_ie);

    csaie->ie = IEEE80211_ELEMID_CHANSWITCHANN;
    csaie->len = 3; /* fixed len */
    csaie->switchmode = 1; /* AP forces STAs in the BSS to stop transmissions until the channel switch completes*/
    csaie->newchannel = next_ch->ic_ieee;
    csaie->tbttcount = tbtt_cnt;

    return frm + csaielen;
}

u_int8_t* add_sec_chan_offset_ie(u_int8_t *frm, struct ieee80211_channel *next_ch)
{
    struct ieee80211_ie_sec_chan_offset *secie = (struct ieee80211_ie_sec_chan_offset*)frm;
    int secielen = sizeof(struct ieee80211_ie_sec_chan_offset);

    secie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;
    secie->len = 1;
    secie->sec_chan_offset = ieee80211_sec_chan_offset(next_ch);

    return frm + secielen;
}
/*
 *  Add next channel info in beacon vendor IE, this will be used when RE detects RADAR and Root does not
 *  RE send RCSAs to Root and CSAs to its clients and switches to the channel that was communicated by its
 *  parent through this vendor IE
 */
u_int8_t *
ieee80211_add_next_channel(u_int8_t *frm, struct ieee80211_node *ni, struct ieee80211com *ic, int subtype)
{
    u_int8_t *efrm;
    u_int8_t ie_len;
    u_int16_t chwidth;
    struct ieee80211_ie_wide_bw_switch *widebw = NULL;
    int widebw_len = sizeof(struct ieee80211_ie_wide_bw_switch);
    struct ieee80211_channel *next_channel = ic->ic_tx_next_ch;
    static const u_int8_t oui[6] = {
        (QCA_OUI & 0xff), ((QCA_OUI >> 8) & 0xff), ((QCA_OUI >> 16) & 0xff),
        QCA_OUI_NC_TYPE, QCA_OUI_NC_SUBTYPE,
        QCA_OUI_NC_VERSION
    };
    /* preserving efrm pointer, if no sub element is present,
        Skip adding this element */
    efrm = frm;
     /* reserving 2 bytes for the element id and element len*/
    frm += 2;

    OS_MEMCPY(frm, oui, IEEE80211_N(oui));
    frm += IEEE80211_N(oui);

    frm = add_chan_switch_ie(frm, next_channel, ic->ic_chan_switch_cnt);

    frm = add_sec_chan_offset_ie(frm, next_channel);

    chwidth = ieee80211_get_chan_width(next_channel);

    if(IEEE80211_IS_CHAN_11AC(next_channel) && chwidth != CHWIDTH_VHT20) {
        /*If channel width not 20 then add Wideband and txpwr evlp element*/
        frm = ieee80211_add_vht_wide_bw_switch(frm, ni, ic, subtype, 1);
    }
    else {
        widebw = (struct ieee80211_ie_wide_bw_switch *)frm;
        OS_MEMSET(widebw, 0, sizeof(struct ieee80211_ie_wide_bw_switch));
        widebw->elem_id = QCA_UNHANDLED_SUB_ELEM_ID;
        widebw->elem_len = widebw_len - 2;
        frm += widebw_len;
    }

    /* If frame is filled with sub elements then add element id and len*/
    if((frm-2) != efrm)
    {
       ie_len = frm - efrm - 2;
       *efrm++ = IEEE80211_ELEMID_VENDOR;
       *efrm = ie_len;
       /* updating efrm with actual index*/
       efrm = frm;
    }
    return efrm;
}
/*
 * Add an Atheros extended capability information element to a frame
 */
u_int8_t *
ieee80211_add_athextcap(u_int8_t *frm, u_int16_t ath_extcap, u_int8_t weptkipaggr_rxdelim)
{
    static const u_int8_t oui[6] = {(ATH_OUI & 0xff),
                                        ((ATH_OUI >>8) & 0xff),
                                        ((ATH_OUI >> 16) & 0xff),
                                        ATH_OUI_EXTCAP_TYPE,
                                        ATH_OUI_EXTCAP_SUBTYPE,
                                        ATH_OUI_EXTCAP_VERSION};

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 10;
    OS_MEMCPY(frm, oui, sizeof(oui));
    frm += sizeof(oui);
    *frm++ = ath_extcap & 0xff;
    *frm++ = (ath_extcap >> 8) & 0xff;
    *frm++ = weptkipaggr_rxdelim & 0xff;
    *frm++ = 0; /* reserved */
    return frm;
}

/*
 * Add a QCA Whole Home Coverage Rept information element to a frame
 */
u_int8_t *
ieee80211_add_whc_rept_info_ie(u_int8_t *frm)
{
    static const u_int8_t oui[6] = {
        (QCA_OUI & 0xff), ((QCA_OUI >> 8) & 0xff), ((QCA_OUI >> 16) & 0xff),
        QCA_OUI_WHC_REPT_TYPE, QCA_OUI_WHC_REPT_INFO_SUBTYPE,
        QCA_OUI_WHC_REPT_INFO_VERSION
    };

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = sizeof(oui);
    OS_MEMCPY(frm, oui, sizeof(oui));
    frm += sizeof(oui);

    return frm;
}


/*
 * Add a QCA Whole Home Coverage AP information element to a frame
 */
u_int8_t *
ieee80211_add_whc_ap_info_ie(u_int8_t *frm, u_int16_t whc_caps,
                             struct ieee80211vap *vap, u_int16_t* ie_len)
{
    static const u_int8_t oui[6] = {
        (QCA_OUI & 0xff), ((QCA_OUI >> 8) & 0xff), ((QCA_OUI >> 16) & 0xff),
        QCA_OUI_WHC_TYPE, QCA_OUI_WHC_AP_INFO_SUBTYPE,
        QCA_OUI_WHC_AP_INFO_VERSION
    };
    u_int8_t *plen = NULL;
    u_int16_t uplink_rate;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    plen = frm++;
    *plen = 9;
    OS_MEMCPY(frm, oui, sizeof(oui));
    frm += sizeof(oui);

    /* Populate the WHC capabilities bit mask in little endian byte order */
    *frm++ = (whc_caps & 0xff);
    *frm++ = ((whc_caps >> 8) & 0xff);

    *frm++ = vap->iv_whc_root_ap_distance;

    *plen += 22;
    if(vap->iv_whc_root_ap_distance == 0)
    {
        /* ROOTAP indicator */
        *frm++ = 1;
        uplink_rate = 0xFFFF;
    }
    else
    {
        /* ROOTAP indicator */
        *frm++ = 0;
        uplink_rate = MIN(vap->iv_ic->ic_serving_ap_backhaul_rate, vap->iv_ic->ic_uplink_rate);
    }
    /* # of connected REs */
    *frm++ = vap->iv_connected_REs;
    /* uplink BSSID of this RE */
    OS_MEMCPY(frm, vap->iv_ic->ic_uplink_bssid, IEEE80211_ADDR_LEN);
    frm += IEEE80211_ADDR_LEN;
    /* uplink(STA) rate of this RE (Little Endian) */
    *frm++ = uplink_rate & 0xff;
    *frm++ = (uplink_rate >> 8) & 0xff;
    if(IEEE80211_IS_CHAN_5GHZ(vap->iv_bsschan))
    {
        OS_MEMCPY(frm, vap->iv_bss->ni_bssid, IEEE80211_ADDR_LEN);
        frm += IEEE80211_ADDR_LEN;
        OS_MEMCPY(frm, vap->iv_ic->ic_otherband_bssid, IEEE80211_ADDR_LEN);
        frm += IEEE80211_ADDR_LEN;
    }
    else
    {
        OS_MEMCPY(frm, vap->iv_ic->ic_otherband_bssid, IEEE80211_ADDR_LEN);
        frm += IEEE80211_ADDR_LEN;
        OS_MEMCPY(frm, vap->iv_bss->ni_bssid, IEEE80211_ADDR_LEN);
        frm += IEEE80211_ADDR_LEN;
    }

    /* return the length of this ie, including element ID and length field */
    *ie_len = (u_int16_t)(*plen + 2);

    return frm;
}

/*
 * Add 802.11h information elements to a frame.
 */
u_int8_t *
ieee80211_add_doth(u_int8_t *frm, struct ieee80211vap *vap)
{
    struct ieee80211_channel *c;
    int    i, j, chancnt;
    u_int8_t *chanlist;
    u_int8_t prevchan;
    u_int8_t *frmbeg;
    struct ieee80211com *ic = vap->iv_ic;

    /* XXX ie structures */
    /*
     * Power Capability IE
     */
    chanlist = OS_MALLOC(ic->ic_osdev, sizeof(u_int8_t) * (IEEE80211_CHAN_MAX + 1), 0);
    if (chanlist == NULL) {
        QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] chanlist is null  \n",__func__,__LINE__);
        return frm;
    }
    *frm++ = IEEE80211_ELEMID_PWRCAP;
    *frm++ = 2;
    *frm++ = vap->iv_bsschan->ic_minpower;
    *frm++ = vap->iv_bsschan->ic_maxpower;

	/*
	 * Supported Channels IE as per 802.11h-2003.
	 */
    frmbeg = frm;
    prevchan = 0;
    chancnt = 0;


    for (i = 0; i < ic->ic_nchans; i++)
    {
        c = &ic->ic_channels[i];

        /* Skip turbo channels */
        if (IEEE80211_IS_CHAN_TURBO(c))
            continue;

        /* Skip half/quarter rate channels */
        if (IEEE80211_IS_CHAN_HALF(c) || IEEE80211_IS_CHAN_QUARTER(c))
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

        if ((c->ic_ieee == (prevchan + 1)) && prevchan) {
            frm[1] = frm[1] + 1;
        } else {
            frm += 2;
            frm[0] =  c->ic_ieee;
            frm[1] = 1;
        }

        prevchan = c->ic_ieee;
    }

    frm += 2;

    if (chancnt) {
        frmbeg[0] = IEEE80211_ELEMID_SUPPCHAN;
        frmbeg[1] = (u_int8_t)(frm - frmbeg - 2);
    } else {
        frm = frmbeg;
    }

    OS_FREE(chanlist);
    return frm;
}

/*
 * Add ht supported rates to HT element.
 * Precondition: the Rx MCS bitmask is zero'd out.
 */
static void
ieee80211_set_htrates(struct ieee80211vap *vap, u_int8_t *rx_mcs, struct ieee80211com *ic)
{
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap),
             rx_streams = ieee80211_get_rxstreams(ic, vap);

    /* First, clear Supported MCS fields. Default to max 1 tx spatial stream */
    rx_mcs[IEEE80211_TX_MCS_OFFSET] &= ~IEEE80211_TX_MCS_SET;

    /* Set Tx MCS Set Defined */
    rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_MCS_SET_DEFINED;

    if (tx_streams != rx_streams) {
        /* Tx MCS Set != Rx MCS Set */
        rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_RX_MCS_SET_NOT_EQUAL;

        switch(tx_streams) {
        case 2:
            rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_2_SPATIAL_STREAMS;
            break;
        case 3:
            rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_3_SPATIAL_STREAMS;
            break;
        case 4:
            rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_4_SPATIAL_STREAMS;
            break;
        }
    }

    /* REVISIT: update bitmask if/when going to > 3 streams */
    switch (rx_streams) {
    default:
        /* Default to single stream */
    case 1:
        /* Advertise all single spatial stream (0-7) mcs rates */
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
    case 2:
        /* Advertise all single & dual spatial stream mcs rates (0-15) */
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
    case 3:
        /* Advertise all single, dual & triple spatial stream mcs rates (0-23) */
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
#if ATH_SUPPORT_4SS
    case 4:
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_4_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
#endif
    }
    if(vap->iv_disable_htmcs) {
        rx_mcs[0] &= ~vap->iv_disabled_ht_mcsset[0];
        rx_mcs[1] &= ~vap->iv_disabled_ht_mcsset[1];
        rx_mcs[2] &= ~vap->iv_disabled_ht_mcsset[2];
        rx_mcs[3] &= ~vap->iv_disabled_ht_mcsset[3];
    }
}

/*
 * Add ht basic rates to HT element.
 */
static void
ieee80211_set_basic_htrates(u_int8_t *frm, const struct ieee80211_rateset *rs)
{
    int i;
    int nrates;

    nrates = rs->rs_nrates;
    if (nrates > IEEE80211_HT_RATE_SIZE)
        nrates = IEEE80211_HT_RATE_SIZE;

    /* set the mcs bit mask from the rates */
    for (i=0; i < nrates; i++) {
        if ((i < IEEE80211_RATE_MAXSIZE) &&
            (rs->rs_rates[i] & IEEE80211_RATE_BASIC))
            *(frm + IEEE80211_RV(rs->rs_rates[i]) / 8) |= 1 << (IEEE80211_RV(rs->rs_rates[i]) % 8);
    }
}

/*
 * Add 802.11n HT Capabilities IE
 */
static void
ieee80211_add_htcap_cmn(struct ieee80211_node *ni, struct ieee80211_ie_htcap_cmn *ie, u_int8_t subtype)
{
    struct ieee80211com       *ic = ni->ni_ic;
    struct ieee80211vap       *vap = ni->ni_vap;
    u_int16_t                 htcap, hc_extcap = 0;
    u_int8_t                  noht40 = 0;
    u_int32_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int32_t tx_streams = ieee80211_get_txstreams(ic, vap);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    htcap = ic->ic_htcap;
    htcap &= (((vap->iv_htflags & IEEE80211_HTF_SHORTGI40) && vap->iv_sgi) ?
                     ic->ic_htcap  : ~IEEE80211_HTCAP_C_SHORTGI40);
    htcap &= (((vap->iv_htflags & IEEE80211_HTF_SHORTGI20) && vap->iv_sgi) ?
                     ic->ic_htcap  : ~IEEE80211_HTCAP_C_SHORTGI20);

    htcap &= (((vap->iv_ldpc & IEEE80211_HTCAP_C_LDPC_RX) &&
              (ieee80211com_get_ldpccap(ic) & IEEE80211_HTCAP_C_LDPC_RX)) ?
              ic->ic_htcap : ~IEEE80211_HTCAP_C_ADVCODING);
    /*
     * Adjust the TX and RX STBC fields based on the chainmask and configuration
     */
    htcap &= (((vap->iv_tx_stbc) && (tx_streams > 1)) ? ic->ic_htcap : ~IEEE80211_HTCAP_C_TXSTBC);
    htcap &= (((vap->iv_rx_stbc) && (rx_streams > 0)) ? ic->ic_htcap : ~IEEE80211_HTCAP_C_RXSTBC);

    /* If bss/regulatory does not allow HT40, turn off HT40 capability */
    if (!(IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT40(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT80(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT160(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT80_80(vap->iv_bsschan))) {
        noht40 = 1;

        /* Don't advertize any HT40 Channel width capability bit */
        /* Advertise HT40 support to interop with 11N HT40 only AP*/
        if(!(vap->iv_opmode == IEEE80211_M_STA)) {
            htcap &= ~IEEE80211_HTCAP_C_CHWIDTH40;
        }
    }

    if (IEEE80211_IS_CHAN_11NA(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11AC(vap->iv_bsschan)) {
        htcap &= ~IEEE80211_HTCAP_C_DSSSCCK40;
    }

    /* Should we advertize HT40 capability on 2.4GHz channels? */
    if (IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) {
        if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
            noht40 = 1;
        } else if (!ic->ic_enable2GHzHt40Cap ||
                   !(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40))
        {
            noht40 = 1;
        }
        if(!ic->ic_enable2GHzHt40Cap)
            htcap &= ~IEEE80211_HTCAP_C_CHWIDTH40;
    }

    if (noht40) {
        /* Don't advertize any HT40 capability bits */
        htcap &= ~(IEEE80211_HTCAP_C_DSSSCCK40 |
                   IEEE80211_HTCAP_C_SHORTGI40);
    }


    if (!ieee80211_vap_dynamic_mimo_ps_is_set(ni->ni_vap)) {
        /* Don't advertise Dynamic MIMO power save if not configured */
        htcap &= ~IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC;
        htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED;
    }

    /* Set support for 20/40 Coexistence Management frame support */
    htcap |= (vap->iv_ht40_intolerant) ? IEEE80211_HTCAP_C_INTOLERANT40 : 0;

    ie->hc_cap = htole16(htcap);

    ie->hc_maxampdu	= ic->ic_maxampdu;
#if ATH_SUPPORT_WAPI
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
       (RSN_CIPHER_IS_SMS4(&vap->iv_rsn))) {
        ie->hc_mpdudensity = 7;
    } else
#endif
    {
        /* MPDU Density : If User provided mpdudensity,
         * Take user configured value*/
        if(ic->ic_mpdudensityoverride) {
            ie->hc_mpdudensity = ic->ic_mpdudensityoverride >> 1;
        } else {
            /* WAR for MPDU DENSITY : In Beacon frame the mpdu density is set as zero. In association response and request if the peer txstreams
             * is 4 set the MPDU density to 16.
             */
            if ((scn->is_ar900b) && (IEEE80211_IS_CHAN_5GHZ(vap->iv_bsschan)) &&
                    ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) || (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ)) &&
                    (MIN(ni->ni_txstreams, rx_streams) == IEEE80211_MAX_SPATIAL_STREAMS)) {
                ie->hc_mpdudensity = IEEE80211_HTCAP_MPDUDENSITY_16;
            } else {
                ie->hc_mpdudensity = ic->ic_mpdudensity;
            }
        }

    }
    ie->hc_reserved	= 0;

    /* Initialize the MCS bitmask */
    OS_MEMZERO(ie->hc_mcsset, sizeof(ie->hc_mcsset));

    /* Set supported MCS set */
    ieee80211_set_htrates(vap, ie->hc_mcsset, ic);
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
            (RSN_CIPHER_IS_WEP(&vap->iv_rsn)
             || (RSN_CIPHER_IS_TKIP(&vap->iv_rsn) && (!RSN_CIPHER_IS_CCMP128(&vap->iv_rsn)) &&
                 (!RSN_CIPHER_IS_CCMP256(&vap->iv_rsn)) &&
                 (!RSN_CIPHER_IS_GCMP128(&vap->iv_rsn)) &&
                 (!RSN_CIPHER_IS_GCMP256(&vap->iv_rsn))))) {
        /*
         * WAR for Tx FIFO underruns with MCS15 in WEP mode. Exclude
         * MCS15 from rates if WEP encryption is set in HT20 mode
         */
        if (IEEE80211_IS_CHAN_11N_HT20(vap->iv_bsschan))
            ie->hc_mcsset[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] &= 0x7F;
    }

#if ATH_SUPPORT_WRAP
    if ((vap->iv_psta == 1)) {
        if ((ic->ic_proxystarxwar == 1) &&
            IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
                IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan) &&
                    (RSN_CIPHER_IS_TKIP(&vap->iv_rsn) || (RSN_CIPHER_IS_CCMP128(&vap->iv_rsn)) ||
                     (RSN_CIPHER_IS_CCMP256(&vap->iv_rsn)) || (RSN_CIPHER_IS_GCMP128(&vap->iv_rsn)) ||
                     (RSN_CIPHER_IS_GCMP256(&vap->iv_rsn)) )) {
                ie->hc_mcsset[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] &= 0x7F;
        }
    }
#endif

#ifdef ATH_SUPPORT_TxBF
    ic->ic_set_txbf_caps(ic);       /* update txbf cap*/
    ie->hc_txbf.value = htole32(ic->ic_txbf.value);

    /* disable TxBF mode for SoftAP mode of win7*/
    if (vap->iv_opmode == IEEE80211_M_HOSTAP){
        if(vap->iv_txbfmode == 0 ){
            ie->hc_txbf.value = 0;
        }
    }
#if ATH_SUPPORT_WRAP
    /* disable TxBF mode for WRAP in case of Direct Attach only*/
    if(!ic->ic_is_mode_offload(ic)) {
            if (vap->iv_wrap || vap->iv_psta)
                    ie->hc_txbf.value = 0;
    }
#endif

#if ATH_SUPPORT_WAPI
    /* disable TxBF mode for WAPI on Direct Attach chips */
    if( !ic->ic_is_mode_offload(ic) && ieee80211_vap_wapi_is_set(vap) )
        ie->hc_txbf.value = 0;
#endif

    if (ie->hc_txbf.value!=0) {
        hc_extcap |= IEEE80211_HTCAP_EXTC_HTC_SUPPORT;    /*enable +HTC support*/
    }
#else
    ie->hc_txbf    = 0;
#endif
    ie->hc_extcap  = htole16(hc_extcap);
    ie->hc_antenna = 0;
}

u_int8_t *
ieee80211_add_htcap(u_int8_t *frm, struct ieee80211_node *ni, u_int8_t subtype)
{
    struct ieee80211_ie_htcap_cmn *ie;
    int htcaplen;
    struct ieee80211_ie_htcap *htcap = (struct ieee80211_ie_htcap *)frm;

    htcap->hc_id      = IEEE80211_ELEMID_HTCAP_ANA;
    htcap->hc_len     = sizeof(struct ieee80211_ie_htcap) - 2;

    ie = &htcap->hc_ie;
    htcaplen = sizeof(struct ieee80211_ie_htcap);

    ieee80211_add_htcap_cmn(ni, ie, subtype);

    return frm + htcaplen;
}

u_int8_t *
ieee80211_add_htcap_vendor_specific(u_int8_t *frm, struct ieee80211_node *ni,u_int8_t subtype)
{
    struct ieee80211_ie_htcap_cmn *ie;
    int htcaplen;
    struct vendor_ie_htcap *htcap = (struct vendor_ie_htcap *)frm;

    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG, "%s: use HT caps IE vendor specific\n",
                      __func__);

    htcap->hc_id      = IEEE80211_ELEMID_VENDOR;
    htcap->hc_oui[0]  = (ATH_HTOUI >> 16) & 0xff;
    htcap->hc_oui[1]  = (ATH_HTOUI >>  8) & 0xff;
    htcap->hc_oui[2]  = ATH_HTOUI & 0xff;
    htcap->hc_ouitype = IEEE80211_ELEMID_HTCAP_VENDOR;
    htcap->hc_len     = sizeof(struct vendor_ie_htcap) - 2;

    ie = &htcap->hc_ie;
    htcaplen = sizeof(struct vendor_ie_htcap);

    ieee80211_add_htcap_cmn(ni, ie,subtype);

    return frm + htcaplen;
}

/*
 * Add 802.11n HT Information IE
 */
/* NB: todo: still need to handle the case for when there may be non-HT STA's on channel (extension
   and/or control) that are not a part of the BSS.  Process beacons for no HT IEs and
   process assoc-req for BS' other than our own */
void
ieee80211_update_htinfo_cmn(struct ieee80211_ie_htinfo_cmn *ie, struct ieee80211_node *ni)
{
    struct ieee80211com        *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t chwidth = 0;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    /*
     ** If the value in the VAP is set, we use that instead of the actual setting
     ** per Srini D.  Hopefully this matches the actual setting.
     */
    if( vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic_cw_width;
    }
    ie->hi_txchwidth = (chwidth == IEEE80211_CWM_WIDTH20) ?
        IEEE80211_HTINFO_TXWIDTH_20 : IEEE80211_HTINFO_TXWIDTH_2040;

    /*
     ** If the value in the VAP for the offset is set, use that per
     ** Srini D.  Otherwise, use the actual setting
     */

    if( vap->iv_chextoffset != 0 ) {
        switch( vap->iv_chextoffset ) {
            case 1:
                ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
                break;
            case 2:
                ie->hi_extchoff =  IEEE80211_HTINFO_EXTOFFSET_ABOVE;
                break;
            case 3:
                ie->hi_extchoff =  IEEE80211_HTINFO_EXTOFFSET_BELOW;
                break;
            default:
                break;
        }
    } else {
        if ((ic_cw_width == IEEE80211_CWM_WIDTH40)||(ic_cw_width == IEEE80211_CWM_WIDTH80) || (ic_cw_width == IEEE80211_CWM_WIDTH160)) {
            switch (ic->ic_cwm_get_extoffset(ic)) {
                case 1:
                    ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_ABOVE;
                    break;
                case -1:
                    ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_BELOW;
                    break;
                case 0:
                default:
                    ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
            }
        } else {
            ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
        }
    }
    if (vap->iv_disable_HTProtection) {
        /* Force HT40: no HT protection*/
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_PURE;
        ie->hi_obssnonhtpresent=IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode = IEEE80211_HTINFO_RIFSMODE_ALLOWED;
    }
    else if (ic->ic_sta_assoc > ic->ic_ht_sta_assoc) {
        /*
         * Legacy stations associated.
         */
        ie->hi_opmode =IEEE80211_HTINFO_OPMODE_MIXED_PROT_ALL;
        ie->hi_obssnonhtpresent = IEEE80211_HTINFO_OBSS_NONHT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_PROHIBITED;
    }
    else if (ieee80211_ic_non_ht_ap_is_set(ic)) {
        /*
         * Overlapping with legacy BSSs.
         */
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_MIXED_PROT_OPT;
        ie->hi_obssnonhtpresent =IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_PROHIBITED;
    }
    else if (ie->hi_txchwidth == IEEE80211_HTINFO_TXWIDTH_2040 && ic->ic_ht_sta_assoc > ic->ic_ht40_sta_assoc) {
        /*
         * HT20 Stations present in HT40 BSS.
         */
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_MIXED_PROT_40;
        ie->hi_obssnonhtpresent = IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_ALLOWED;
    } else {
        /*
         * all Stations are HT40 capable
         */
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_PURE;
        ie->hi_obssnonhtpresent=IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_ALLOWED;
    }
    if ((IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) || IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap)) {
        /*
         *All VHT AP should have RIFS bit set to 0
         */
        ie->hi_rifsmode = IEEE80211_HTINFO_RIFSMODE_PROHIBITED;
    }

    if (vap->iv_opmode != IEEE80211_M_IBSS &&
                ic->ic_ht_sta_assoc > ic->ic_ht_gf_sta_assoc)
        ie->hi_nongfpresent = 1;
    else
        ie->hi_nongfpresent = 0;

    if (!ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        if ((ic_cw_width == IEEE80211_CWM_WIDTH160) && vap->iv_ext_nss_support &&
                 (!(nssmap.flag & IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW))) {
            HTINFO_CCFS2_SET(vap->iv_bsschan->ic_vhtop_ch_freq_seg2, ie);
        }
    }
}

static void
ieee80211_add_htinfo_cmn(struct ieee80211_node *ni, struct ieee80211_ie_htinfo_cmn *ie)
{
    struct ieee80211com        *ic = ni->ni_ic;
    struct ieee80211vap        *vap = ni->ni_vap;

    OS_MEMZERO(ie, sizeof(struct ieee80211_ie_htinfo_cmn));

    /* set control channel center in IE */
    ie->hi_ctrlchannel 	= ieee80211_chan2ieee(ic, vap->iv_bsschan);

    ieee80211_update_htinfo_cmn(ie,ni);
    /* Set the basic MCS Set */
    OS_MEMZERO(ie->hi_basicmcsset, sizeof(ie->hi_basicmcsset));
    ieee80211_set_basic_htrates(ie->hi_basicmcsset, &ni->ni_htrates);

    ieee80211_update_htinfo_cmn(ie, ni);
}

u_int8_t *
ieee80211_add_htinfo(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_htinfo_cmn *ie;
    int htinfolen;
    struct ieee80211_ie_htinfo *htinfo = (struct ieee80211_ie_htinfo *)frm;

    htinfo->hi_id      = IEEE80211_ELEMID_HTINFO_ANA;
    htinfo->hi_len     = sizeof(struct ieee80211_ie_htinfo) - 2;

    ie = &htinfo->hi_ie;
    htinfolen = sizeof(struct ieee80211_ie_htinfo);

    ieee80211_add_htinfo_cmn(ni, ie);

    return frm + htinfolen;
}

u_int8_t *
ieee80211_add_htinfo_vendor_specific(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_htinfo_cmn *ie;
    int htinfolen;
    struct vendor_ie_htinfo *htinfo = (struct vendor_ie_htinfo *) frm;

    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG, "%s: use HT info IE vendor specific\n",
                      __func__);

    htinfo->hi_id      = IEEE80211_ELEMID_VENDOR;
    htinfo->hi_oui[0]  = (ATH_HTOUI >> 16) & 0xff;
    htinfo->hi_oui[1]  = (ATH_HTOUI >>  8) & 0xff;
    htinfo->hi_oui[2]  = ATH_HTOUI & 0xff;
    htinfo->hi_ouitype = IEEE80211_ELEMID_HTINFO_VENDOR;
    htinfo->hi_len     = sizeof(struct vendor_ie_htinfo) - 2;

    ie = &htinfo->hi_ie;
    htinfolen = sizeof(struct vendor_ie_htinfo);

    ieee80211_add_htinfo_cmn(ni, ie);

    return frm + htinfolen;
}

/*
 * Add ext cap element.
 */
u_int8_t *
ieee80211_add_extcap(u_int8_t *frm,struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_ie_ext_cap *ie = (struct ieee80211_ie_ext_cap *) frm;
    u_int32_t ext_capflags = 0;
    u_int32_t ext_capflags2 = 0;
    u_int8_t ext_capflags3 = 0;
    u_int8_t ext_capflags4 = 0;
    u_int32_t ie_elem_len = 0;

    if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
        ext_capflags |= IEEE80211_EXTCAPIE_2040COEXTMGMT;
    }
    ieee80211_wnm_add_extcap(ni, &ext_capflags);

#if UMAC_SUPPORT_PROXY_ARP
    if (ieee80211_vap_proxyarp_is_set(vap) &&
        vap->iv_opmode == IEEE80211_M_HOSTAP)
    {
        ext_capflags |= IEEE80211_EXTCAPIE_PROXYARP;
    }
#endif
#if ATH_SUPPORT_HS20
    if (vap->iv_hotspot_xcaps) {
        ext_capflags |= vap->iv_hotspot_xcaps;
    }
    if (vap->iv_hotspot_xcaps2) {
        ext_capflags2 |= vap->iv_hotspot_xcaps2;
    }
#endif
    if (vap->rtt_enable) {
        /* Date: 6/5/201. we may need seperate control of
            these bits. Setting these bits will follow
            evolution of 802.11mc spec */
        ext_capflags3 |= IEEE80211_EXTCAPIE_FTM_RES;
        ext_capflags3 |= IEEE80211_EXTCAPIE_FTM_INIT;
    }

    if (vap->lcr_enable) {
        ext_capflags |= IEEE80211_EXTCAPIE_CIVLOC;
    }

    if (vap->lci_enable) {
        ext_capflags |= IEEE80211_EXTCAPIE_GEOLOC;
    }

    if (vap->iv_enable_ecsaie) {
        ext_capflags |= IEEE80211_EXTCAPIE_ECSA;
    }

    /* Support reception of Operating Mode notification */
    ext_capflags2 |= IEEE80211_EXTCAPIE_OP_MODE_NOTIFY;

#if UMAC_SUPPORT_FILS
    if(IEEE80211_VAP_IS_FILS_ENABLED(vap)) {
        ext_capflags4 |= IEEE80211_EXTCAPIE_FILS;
    }
#endif

    if (ext_capflags || ext_capflags2 || (ext_capflags3 && vap->rtt_enable) ||
       (ext_capflags4 && IEEE80211_VAP_IS_FILS_ENABLED(vap))) {

        if(IEEE80211_VAP_IS_FILS_ENABLED(vap)) {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap);
        } else if (vap->rtt_enable) {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap) - sizeof(ie->ext_capflags4);
        } else {
            ie_elem_len = (sizeof(struct ieee80211_ie_ext_cap) -
                          (sizeof(ie->ext_capflags3) + sizeof(ie->ext_capflags4)));
        }

        OS_MEMSET(ie, 0, sizeof(struct ieee80211_ie_ext_cap));
        ie->elem_id = IEEE80211_ELEMID_XCAPS;
        ie->elem_len = ie_elem_len - 2;
        ie->ext_capflags = htole32(ext_capflags);
        ie->ext_capflags2 = htole32(ext_capflags2);
        ie->ext_capflags3 = ext_capflags3;
        ie->ext_capflags4 = ext_capflags4;
        return (frm + ie_elem_len);
    }
    else {
        return frm;
    }
}

#if ATH_SUPPORT_HS20
u_int8_t *ieee80211_add_qosmapset(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_qos_map *qos_map = &vap->iv_qos_map;
    struct ieee80211_ie_qos_map_set *ie_qos_map_set =
        (struct ieee80211_ie_qos_map_set *)frm;
    u_int8_t *pos = ie_qos_map_set->qos_map_set;
    u_int8_t len, elem_len = 0;

    if (qos_map->valid && ni->ni_qosmap_enabled) {
        if (qos_map->num_dscp_except) {
            len = qos_map->num_dscp_except *
                  sizeof(struct ieee80211_dscp_exception);
            OS_MEMCPY(pos, qos_map->dscp_exception, len);
            elem_len += len;
            pos += len;
        }

        len = IEEE80211_MAX_QOS_UP_RANGE * sizeof(struct ieee80211_dscp_range);
        OS_MEMCPY(pos, qos_map->up, len);
        elem_len += len;
        pos += len;

        ie_qos_map_set->elem_id = IEEE80211_ELEMID_QOS_MAP;
        ie_qos_map_set->elem_len = elem_len;

        return pos;

    } else {
        /* QoS Map is not valid or not enabled */
        return frm;
    }
}
#endif /* ATH_SUPPORT_HS20 */

/*
 * Update overlapping bss scan element.
 */
void
ieee80211_update_obss_scan(struct ieee80211_ie_obss_scan *ie,
                           struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;

    if ( ie == NULL )
        return;

    ie->scan_interval = (vap->iv_chscaninit) ?
          htole16(vap->iv_chscaninit):htole16(IEEE80211_OBSS_SCAN_INTERVAL_DEF);
}

/*
 * Add overlapping bss scan element.
 */
u_int8_t *
ieee80211_add_obss_scan(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_obss_scan *ie = (struct ieee80211_ie_obss_scan *) frm;

    OS_MEMSET(ie, 0, sizeof(struct ieee80211_ie_obss_scan));
    ie->elem_id = IEEE80211_ELEMID_OBSS_SCAN;
    ie->elem_len = sizeof(struct ieee80211_ie_obss_scan) - 2;
    ieee80211_update_obss_scan(ie, ni);
    ie->scan_passive_dwell = htole16(IEEE80211_OBSS_SCAN_PASSIVE_DWELL_DEF);
    ie->scan_active_dwell = htole16(IEEE80211_OBSS_SCAN_ACTIVE_DWELL_DEF);
    ie->scan_passive_total = htole16(IEEE80211_OBSS_SCAN_PASSIVE_TOTAL_DEF);
    ie->scan_active_total = htole16(IEEE80211_OBSS_SCAN_ACTIVE_TOTAL_DEF);
    ie->scan_thresh = htole16(IEEE80211_OBSS_SCAN_THRESH_DEF);
    ie->scan_delay = htole16(IEEE80211_OBSS_SCAN_DELAY_DEF);
    return frm + sizeof (struct ieee80211_ie_obss_scan);
}

/*
 * routines to parse the IEs received from management frames.
 */
u_int32_t
ieee80211_parse_mpdudensity(u_int32_t mpdudensity)
{
    /*
     * 802.11n D2.0 defined values for "Minimum MPDU Start Spacing":
     *   0 for no restriction
     *   1 for 1/4 us
     *   2 for 1/2 us
     *   3 for 1 us
     *   4 for 2 us
     *   5 for 4 us
     *   6 for 8 us
     *   7 for 16 us
     */
    switch (mpdudensity) {
    case 0:
        return 0;
    case 1:
    case 2:
    case 3:
        /* Our lower layer calculations limit our precision to 1 microsecond */
        return 1;
    case 4:
        return 2;
    case 5:
        return 4;
    case 6:
        return 8;
    case 7:
        return 16;
    default:
        return 0;
    }
}

int
ieee80211_parse_htcap(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_htcap_cmn *htcap = (struct ieee80211_ie_htcap_cmn *)ie;
    struct ieee80211com   *ic = ni->ni_ic;
    struct ieee80211vap   *vap = ni->ni_vap;
    u_int8_t rx_mcs;
    int                    htcapval, prev_htcap = ni->ni_htcap;
    u_int32_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int32_t tx_streams = ieee80211_get_txstreams(ic, vap);

    htcapval    = le16toh(htcap->hc_cap);
    rx_mcs = htcap->hc_mcsset[IEEE80211_TX_MCS_OFFSET];

    rx_mcs &= IEEE80211_TX_MCS_SET;

    if (rx_mcs & IEEE80211_TX_MCS_SET_DEFINED) {
        if( !(rx_mcs & IEEE80211_TX_RX_MCS_SET_NOT_EQUAL) &&
             (rx_mcs & (IEEE80211_TX_MAXIMUM_STREAMS_MASK |IEEE80211_TX_UNEQUAL_MODULATION_MASK))){
            return 0;
        }
    } else {
        if (rx_mcs & IEEE80211_TX_MCS_SET){
            return 0;
        }
    }

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        /*
         * Check if SM powersav state changed.
         * prev_htcap == 0 => htcap set for the first time.
         */
        switch (htcapval & IEEE80211_HTCAP_C_SM_MASK) {
            case IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED:
                if (((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                     IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED) || !prev_htcap) {
                    /*
                     * Station just disabled SM Power Save therefore we can
                     * send to it at full SM/MIMO.
                     */
                    ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                    ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED;
                    ni->ni_updaterates = IEEE80211_NODE_SM_EN;
                    IEEE80211_DPRINTF(ni->ni_vap,IEEE80211_MSG_POWER,"%s:SM"
                                      " powersave disabled\n", __func__);
                }
                break;
            case IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC:
                if (((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                     IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC) || !prev_htcap) {
                    /*
                     * Station just enabled static SM power save therefore
                     * we can only send to it at single-stream rates.
                     */
                    ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                    ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC;
                    ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_STAT;
                    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER,
                                      "%s:switching to static SM power save\n", __func__);
                }
                break;
            case IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC:
                if (((ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) !=
                     IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC) || !prev_htcap) {
                    /*
                     * Station just enabled dynamic SM power save therefore
                     * we should precede each packet we send to it with
                     * an RTS.
                     */
                    ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
                    ni->ni_htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC;
                    ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_DYN;
                    IEEE80211_DPRINTF(ni->ni_vap,IEEE80211_MSG_POWER,
                                      "%s:switching to dynamic SM power save\n",__func__);
                }
        }
        IEEE80211_DPRINTF(ni->ni_vap,IEEE80211_MSG_POWER,
                          "%s:calculated updaterates %#x\n",__func__, ni->ni_updaterates);

        ni->ni_htcap = (htcapval & ~IEEE80211_HTCAP_C_SM_MASK) |
            (ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK);

        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER, "%s: ni_htcap %#x\n",
                          __func__, ni->ni_htcap);

        if (htcapval & IEEE80211_HTCAP_C_GREENFIELD)
            ni->ni_htcap |= IEEE80211_HTCAP_C_GREENFIELD;

    } else {
        ni->ni_htcap = htcapval;
    }

        if (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40)
            ni->ni_htcap  = ni->ni_htcap & (((vap->iv_htflags & IEEE80211_HTF_SHORTGI40) && vap->iv_sgi)
                                        ? ni->ni_htcap  : ~IEEE80211_HTCAP_C_SHORTGI40);
        if (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20)
            ni->ni_htcap  = ni->ni_htcap & (((vap->iv_htflags & IEEE80211_HTF_SHORTGI20) && vap->iv_sgi)
                                        ? ni->ni_htcap  : ~IEEE80211_HTCAP_C_SHORTGI20);

    if (ni->ni_htcap & IEEE80211_HTCAP_C_ADVCODING) {
        if (((vap->iv_ldpc & IEEE80211_HTCAP_C_LDPC_TX) == 0) ||
            ((ieee80211com_get_ldpccap(ic) & IEEE80211_HTCAP_C_LDPC_TX) == 0))
            ni->ni_htcap &= ~IEEE80211_HTCAP_C_ADVCODING;
    }

    if (ni->ni_htcap & IEEE80211_HTCAP_C_TXSTBC) {
        ni->ni_htcap  = ni->ni_htcap & (((vap->iv_rx_stbc) && (rx_streams > 1)) ? ni->ni_htcap : ~IEEE80211_HTCAP_C_TXSTBC);
    }

    /* Tx on our side and Rx on the remote side should be considered for STBC with rate control */
    if (ni->ni_htcap & IEEE80211_HTCAP_C_RXSTBC) {
        ni->ni_htcap  = ni->ni_htcap & (((vap->iv_tx_stbc) && (tx_streams > 1)) ? ni->ni_htcap : ~IEEE80211_HTCAP_C_RXSTBC);
    }

    /* Note: when 11ac is enabled the VHTCAP Channel width will override this */
    if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
        ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
    } else {
        /* Channel width needs to be set to 40MHz for both 40MHz and 80MHz mode */
        if (ic->ic_cwm_get_width(ic) != IEEE80211_CWM_WIDTH20) {
            ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
        }
    }

    if ((ni->ni_htcap & IEEE80211_HTCAP_C_INTOLERANT40) &&
        (IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan))) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER,
                 "%s: Received htcap with 40 intolerant bit set\n", __func__);
        ni->ni_flags |= IEEE80211_NODE_40_INTOLERANT;
    }

    /*
     * The Maximum Rx A-MPDU defined by this field is equal to
     *      (2^^(13 + Maximum Rx A-MPDU Factor)) - 1
     * octets.  Maximum Rx A-MPDU Factor is an integer in the
     * range 0 to 3.
     */

    ni->ni_maxampdu = ((1u << (IEEE80211_HTCAP_MAXRXAMPDU_FACTOR + htcap->hc_maxampdu)) - 1);
    ni->ni_mpdudensity = ieee80211_parse_mpdudensity(htcap->hc_mpdudensity);

    ni->ni_flags |= IEEE80211_NODE_HT;

#ifdef ATH_SUPPORT_TxBF

#if ATH_SUPPORT_WAPI
    if(ic->ic_is_mode_offload(ic) || !ieee80211_vap_wapi_is_set(vap)) {
#endif

#if ATH_SUPPORT_WRAP
        /* disable TxBF mode for WRAP in case of Direct Attach only*/
        if(ic->ic_is_mode_offload(ic) || !(vap->iv_wrap || vap->iv_psta)) {
#endif
		ni->ni_mmss = htcap->hc_mpdudensity;
		ni->ni_txbf.value = le32toh(htcap->hc_txbf.value);
		//IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s:get remote txbf ie %x\n",__func__,ni->ni_txbf.value);
		ieee80211_match_txbfcapability(ic, ni);
		//IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s:final result Com ExBF %d, NonCOm ExBF %d, ImBf %d\n",
		//  __func__,ni->ni_explicit_compbf,ni->ni_explicit_noncompbf,ni->ni_implicit_bf );
#if ATH_SUPPORT_WRAP
	}
#endif

#if ATH_SUPPORT_WAPI
    }
#endif

#endif
    if (ic->ic_set_ampduparams) {
        /* Notify LMAC of the ampdu params */
        ic->ic_set_ampduparams(ni);
    }
    return 1;
}

void
ieee80211_parse_htinfo(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_htinfo_cmn  *htinfo = (struct ieee80211_ie_htinfo_cmn *)ie;
    enum ieee80211_cwm_width    chwidth;
    int8_t extoffset;

    switch(htinfo->hi_extchoff) {
    case IEEE80211_HTINFO_EXTOFFSET_ABOVE:
        extoffset = 1;
        break;
    case IEEE80211_HTINFO_EXTOFFSET_BELOW:
        extoffset = -1;
        break;
    case IEEE80211_HTINFO_EXTOFFSET_NA:
    default:
        extoffset = 0;
    }

    chwidth = IEEE80211_CWM_WIDTH20;
    if (extoffset && (htinfo->hi_txchwidth == IEEE80211_HTINFO_TXWIDTH_2040)) {
        chwidth = IEEE80211_CWM_WIDTH40;
    }

    /* update node's recommended tx channel width */
    ni->ni_chwidth = chwidth;

    /* update node's ext channel offset */
    ni->ni_extoffset = extoffset;

    /* update other HT information */
    ni->ni_obssnonhtpresent = htinfo->hi_obssnonhtpresent;
    ni->ni_txburstlimit     = htinfo->hi_txburstlimit;
    ni->ni_nongfpresent     = htinfo->hi_nongfpresent;
}

int
ieee80211_check_mu_client_cap(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct      ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)ie;
    int         status = 0;

    ni->ni_mu_vht_cap = 0;
    ni->ni_vhtcap = le32toh(vhtcap->vht_cap_info);
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE)
    {
        ni->ni_mu_vht_cap = 1;
        status = 1;
    }
    return status;
}

void
ieee80211_parse_vhtcap(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)ie;
    struct ieee80211com  *ic = ni->ni_ic;
    struct ieee80211vap  *vap = ni->ni_vap;
    u_int32_t ampdu_len = 0;
    u_int8_t chwidth = 0;
    u_int32_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int32_t tx_streams = ieee80211_get_txstreams(ic, vap);
    struct supp_tx_mcs_extnss tx_mcs_extnss_cap;

    /* Negotiated capability set */
    ni->ni_vhtcap = le32toh(vhtcap->vht_cap_info);
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_80) {
        ni->ni_vhtcap  = ni->ni_vhtcap & ((vap->iv_sgi) ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_SHORTGI_80);
    }
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_LDPC) {
        ni->ni_vhtcap  = ni->ni_vhtcap & ((vap->iv_ldpc & IEEE80211_HTCAP_C_LDPC_TX) ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_RX_LDPC);
    }
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_TX_STBC) {
        ni->ni_vhtcap  = ni->ni_vhtcap & (((vap->iv_rx_stbc) && (rx_streams > 1)) ? ni->ni_vhtcap : ~IEEE80211_VHTCAP_TX_STBC);
    }

    /* Tx on our side and Rx on the remote side should be considered for STBC with rate control */
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_STBC) {
        ni->ni_vhtcap  = ni->ni_vhtcap & (((vap->iv_tx_stbc) && (tx_streams > 1)) ? ni->ni_vhtcap : ~IEEE80211_VHTCAP_RX_STBC);
    }

    if (ni->ni_vhtcap & IEEE80211_VHTCAP_SU_BFORMEE) {
        ni->ni_vhtcap  = ni->ni_vhtcap & (vap->iv_vhtsubfer ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_SU_BFORMEE);
    }

    if (ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE) {
        ni->ni_vhtcap  = ni->ni_vhtcap & ((vap->iv_vhtmubfer && vap->iv_vhtsubfer) ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_MU_BFORMEE);
    }

    if (vap->iv_ext_nss_capable) {
        ni->ni_ext_nss_support  = (ni->ni_vhtcap & IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_MASK) >>
                                    IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_S;
    }

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic->ic_cwm_get_width(ic);
    }

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        switch(chwidth) {
            case IEEE80211_CWM_WIDTH20:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            break;

            case IEEE80211_CWM_WIDTH40:
                /* HTCAP Channelwidth will be set to max for VHT as well ? */
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                }
            break;

            case IEEE80211_CWM_WIDTH80:
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else if (!(ni->ni_vhtcap)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                }
            break;
            case IEEE80211_CWM_WIDTH160:
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else if (!(ni->ni_vhtcap)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                } else {
                    if(vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT160) {
                        if (vap->iv_ext_nss_capable && peer_ext_nss_capable(vhtcap) &&
                                (ext_nss_160_supported(&ni->ni_vhtcap) || ext_nss_80p80_supported(&ni->ni_vhtcap))){
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                        } else if((ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160) || (ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160)) {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                        } else {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                        }
                    }
                    else if(vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT80_80) {
                        if (vap->iv_ext_nss_capable && peer_ext_nss_capable(vhtcap) && ext_nss_80p80_supported(&ni->ni_vhtcap)){
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                        } else if(ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160) {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                        } else {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                        }
                    }
                    else {
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                    }
                }

                break;
            default:
                /* Do nothing */
            break;
        }
    }


    if (ni->ni_chwidth == IEEE80211_CWM_WIDTH160) {
        ni->ni_160bw_requested = 1;
    }
    else {
        ni->ni_160bw_requested = 0;
    }

    /*
     * The Maximum Rx A-MPDU defined by this field is equal to
     *   (2^^(13 + Maximum Rx A-MPDU Factor)) - 1
     * octets.  Maximum Rx A-MPDU Factor is an integer in the
     * range 0 to 7.
     */

    ampdu_len = (le32toh(vhtcap->vht_cap_info) & IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP) >> IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S;
    ni->ni_maxampdu = (1u << (IEEE80211_VHTCAP_MAX_AMPDU_LEN_FACTOR + ampdu_len)) -1;
    ni->ni_flags |= IEEE80211_NODE_VHT;
    ni->ni_tx_vhtrates = le16toh(vhtcap->tx_mcs_map);
    ni->ni_rx_vhtrates = le16toh(vhtcap->rx_mcs_map);
    ni->ni_rx_max_rate = le16toh(vhtcap->rx_high_data_rate);
    OS_MEMCPY(&tx_mcs_extnss_cap,&vhtcap->tx_mcs_extnss_cap,sizeof(u_int16_t));
    *(u_int16_t *)&tx_mcs_extnss_cap = le16toh(*(u_int16_t*)&tx_mcs_extnss_cap);
    ni->ni_tx_max_rate = (tx_mcs_extnss_cap.tx_high_data_rate);
    ni->ni_ext_nss_capable  = ((tx_mcs_extnss_cap.ext_nss_capable && vap->iv_ext_nss_capable) ? 1:0);

    if ( vap->iv_ext_nss_capable && ni->ni_ext_nss_support) {
         ieee80211_derive_nss_from_cap(ni);
     }
}

void
ieee80211_parse_vhtop(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t *htinfo_ie)
{
    struct ieee80211_ie_vhtop *vhtop = (struct ieee80211_ie_vhtop *)ie;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int ch_width;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    struct ieee80211_ie_htinfo_cmn  *htinfo = (struct ieee80211_ie_htinfo_cmn *)htinfo_ie;
    switch (vhtop->vht_op_chwidth) {
       case IEEE80211_VHTOP_CHWIDTH_2040:
           /* Exact channel width is already taken care of by the HT parse */
       break;
       case IEEE80211_VHTOP_CHWIDTH_80:
       if (vap->iv_ext_nss_capable) {
            if ((extnss_160_validate_and_seg2_indicate(&ni->ni_vhtcap, vhtop, htinfo)) ||
                        (extnss_80p80_validate_and_seg2_indicate(&ni->ni_vhtcap, vhtop, htinfo))) {
                ni->ni_chwidth =  IEEE80211_CWM_WIDTH160;
            } else {
                ni->ni_chwidth =  IEEE80211_CWM_WIDTH80;
            }
       }
       else if (IS_REVSIG_VHT160(vhtop) || IS_REVSIG_VHT80_80(vhtop)) {
               ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
       } else {
           ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
       }
       break;
       case IEEE80211_VHTOP_CHWIDTH_160:
       case IEEE80211_VHTOP_CHWIDTH_80_80:
           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
       break;
       default:
           IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
                            "%s: Unsupported Channel Width\n", __func__);
       break;
    }

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        ch_width = vap->iv_chwidth;
    } else {
        ch_width = ic_cw_width;
    }
    /* Update ch_width only if it is within the user configured width*/
    if(ch_width < ni->ni_chwidth) {
        ni->ni_chwidth = ch_width;
    }
}

void
ieee80211_add_opmode(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype)
{
    struct ieee80211_ie_op_mode *opmode = (struct ieee80211_ie_op_mode *)frm;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t nss = vap->iv_nss;
    u_int8_t ch_width = 0;
    ieee80211_vht_rate_t ni_tx_vht_rates;


    if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
        (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Check negotiated Rx NSS and chwidth */
        ieee80211_get_vht_rates(ni->ni_tx_vhtrates, &ni_tx_vht_rates);
        rx_streams = MIN(rx_streams, ni_tx_vht_rates.num_streams);
        /* Set negotiated BW */
        ch_width = ni->ni_chwidth;
    } else {
        /* Fill in default channel width */
        if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
            ch_width = vap->iv_chwidth;
        } else {
            ch_width = ic_cw_width;
        }
    }

    opmode->reserved = 0;
    opmode->rx_nss_type = 0; /* No beamforming */
    opmode->rx_nss = nss < rx_streams ? (nss-1) : (rx_streams -1); /* Supported RX streams */
    if (vap->iv_ext_nss_support && (ch_width == IEEE80211_CWM_WIDTH160 || ch_width == IEEE80211_CWM_WIDTH80_80)) {
        opmode->bw_160_80p80 = 1;
    } else {
        opmode->ch_width = ch_width;
    }
}

u_int8_t *
ieee80211_add_opmode_notify(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype)
{
    struct ieee80211_ie_op_mode_ntfy *opmode = (struct ieee80211_ie_op_mode_ntfy *)frm;
    int opmode_notify_len = sizeof(struct ieee80211_ie_op_mode_ntfy);

    opmode->elem_id   = IEEE80211_ELEMID_OP_MODE_NOTIFY;
    opmode->elem_len  =  opmode_notify_len- 2;
    ieee80211_add_opmode((u_int8_t *)&opmode->opmode, ni, ic, subtype);
    return frm + opmode_notify_len;
}

int  ieee80211_intersect_extnss_160_80p80(struct ieee80211_node *ni)
{
    struct ieee80211com  *ic = ni->ni_ic;
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, ni->ni_vap);
    struct ieee80211_bwnss_map nssmap;
    u_int32_t min_nss_160, min_nss_80_80 = 0;

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    if (!ieee80211_get_bw_nss_mapping(ni->ni_vap, &nssmap, tx_streams)) {
        if (!ieee80211_derive_nss_from_cap(ni)) {
            return 0;
        }
        min_nss_160 = MIN(nssmap.bw_nss_160, IEEE80211_GET_BW_NSS_FWCONF_160(ni->ni_bwnss_map));
        min_nss_80_80 = MIN(nssmap.bw_nss_160, IEEE80211_GET_BW_NSS_FWCONF_80_80(ni->ni_bwnss_map));
        ni->ni_bwnss_map = IEEE80211_BW_NSS_FWCONF_160(min_nss_160) | IEEE80211_BW_NSS_FWCONF_80_80(min_nss_80_80);
    }
    return 1;
}

void
ieee80211_parse_opmode(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype)
{
    struct ieee80211_ie_op_mode *opmode = (struct ieee80211_ie_op_mode *)ie;
    struct ieee80211com  *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, ni->ni_vap);
    u_int8_t rx_nss = 0;
#if ATH_BAND_STEERING
    bool generate_event = false;
#endif
    bool chwidth_change = false;

    /* In conformance with the standard, we add a check to ensure that
     * we don't parse Operating Mode received from an unassociated client
     * except if sent in an association related frame. Note that the
     * authorization state of the client does not matter.
     */
    if ((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
        (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP) &&
        (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_REQ) &&
        (subtype != IEEE80211_FC0_SUBTYPE_ASSOC_REQ)) {
        if (ic->ic_opmode == IEEE80211_M_STA) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
            "%s: Not parsing opmode in client mode\n",__func__);
            return;
        }
        if ((ic->ic_opmode == IEEE80211_M_HOSTAP) && !(IEEE80211_IS_MYSTA(vap, ni))) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
            "%s: Not associated.\n",__func__);
            return;
        }
    }

    /* Check whether this is a beamforming type */
    if (opmode->rx_nss_type == 1) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
                           "%s: Beamforming is unsupported\n", __func__);
        return;
    }

    /* Update ch_width for peer only if it is within the bw supported */
    if ((!vap->iv_ext_nss_capable || !ni->ni_ext_nss_support || !opmode->bw_160_80p80)
                   && (opmode->ch_width <= ic_cw_width) &&
                   (opmode->ch_width != ni->ni_chwidth)) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
            "%s: Bandwidth changed from %d to %d \n",
             __func__, ni->ni_chwidth, opmode->ch_width);
        switch (opmode->ch_width) {
            case 0:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                chwidth_change = true;
            break;

            case 1:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                chwidth_change = true;
            break;

            case 2:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                chwidth_change = true;
            break;

            case 3:
                if (!vap->iv_ext_nss_capable) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                    chwidth_change = true;
                }
                    break;

            default:
                IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
                           "%s: Unsupported Channel Width\n", __func__);
                return;
            break;
        }
    }
    if (vap->iv_ext_nss_capable && ni->ni_ext_nss_support && opmode->bw_160_80p80 &&
             (ic_cw_width >= IEEE80211_CWM_WIDTH160) && (ni->ni_chwidth != IEEE80211_CWM_WIDTH160)) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
            "%s: Bandwidth changed from %d to 3 \n",
             __func__, ni->ni_chwidth);
        chwidth_change = true;
        ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
    }
    if (chwidth_change == true ) {

        if ((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_REQ) &&
            (subtype != IEEE80211_FC0_SUBTYPE_ASSOC_REQ)) {
            ic->ic_chwidth_change(ni);
#if ATH_BAND_STEERING
            generate_event = true;
#endif
        }
    }

    /* Propagate the number of Spatial streams to the target */
    rx_nss = opmode->rx_nss + 1;
    if ((rx_nss != ni->ni_streams) && (rx_nss <= tx_streams)) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
             "%s: NSS changed from %d to %d \n", __func__, ni->ni_streams, opmode->rx_nss + 1);

        ni->ni_streams = rx_nss;

        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH160) && ni->ni_ext_nss_support && vap->iv_ext_nss_support){
             ieee80211_intersect_extnss_160_80p80(ni);
        }

        if ((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_REQ) &&
            (subtype != IEEE80211_FC0_SUBTYPE_ASSOC_REQ)) {
            ic->ic_nss_change(ni);
#if ATH_BAND_STEERING
            generate_event = true;
#endif
        }
    }

#if ATH_BAND_STEERING
    if (generate_event) {
        ieee80211_bsteering_send_opmode_update_event(ni->ni_vap, ni);
    }
#endif
}

void
ieee80211_parse_opmode_notify(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype)
{
    struct ieee80211_ie_op_mode_ntfy *opmode = (struct ieee80211_ie_op_mode_ntfy *)ie;
    ieee80211_parse_opmode(ni, (u_int8_t *)&opmode->opmode, subtype);
}

int
ieee80211_parse_dothparams(struct ieee80211vap *vap, u_int8_t *frm)
{
    struct ieee80211com *ic = vap->iv_ic;
    u_int len = frm[1];
    u_int8_t chan, tbtt;

    if (len < 4-2) {        /* XXX ie struct definition */
        IEEE80211_DISCARD_IE(vap,
                             IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
                             "channel switch", "too short, len %u", len);
        return -1;
    }
    chan = frm[3];
    if (isclr(ic->ic_chan_avail, chan)) {
        IEEE80211_DISCARD_IE(vap,
                             IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
                             "channel switch", "invalid channel %u", chan);
        return -1;
    }
    tbtt = frm[4];
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                      "%s: channel switch to %d in %d tbtt\n", __func__, chan, tbtt);
    if (tbtt <= 1) {
        struct ieee80211_channel *c;

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                          "%s: Channel switch to %d NOW!\n", __func__, chan);
        if ((c = ieee80211_doth_findchan(vap, chan)) == NULL) {
            /* XXX something wrong */
            IEEE80211_DISCARD_IE(vap,
                                 IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
                                 "channel switch",
                                 "channel %u lookup failed", chan);
            return 0;
        }
        vap->iv_bsschan = c;
        ieee80211_set_channel(ic, c);
        return 1;
    }
    return 0;
}

int
ieee80211_parse_wmeparams(struct ieee80211vap *vap, u_int8_t *frm,
                          u_int8_t *qosinfo, int forced_update)
{
#undef MS
#define MS(_v, _f)  (((_v) & _f) >> _f##_S)
    struct ieee80211_wme_state *wme = &vap->iv_ic->ic_wme;
    u_int len = frm[1], qosinfo_count;
    int i;

    *qosinfo = 0;

    if (len < sizeof(struct ieee80211_wme_param) - 2) {
        /* XXX: TODO msg+stats */
        return -1;
    }

    *qosinfo = frm[__offsetof(struct ieee80211_wme_param, param_qosInfo)];
    qosinfo_count = *qosinfo & WME_QOSINFO_COUNT;

    if (!forced_update) {

   	 /* XXX do proper check for wraparound */
    	if (qosinfo_count == (wme->wme_wmeChanParams.cap_info & WME_QOSINFO_COUNT))
        	return 0;
    }

    frm += __offsetof(struct ieee80211_wme_param, params_acParams);
    for (i = 0; i < WME_NUM_AC; i++) {
        struct wmeParams *wmep =
            &wme->wme_wmeChanParams.cap_wmeParams[i];
        /* NB: ACI not used */
        wmep->wmep_acm = MS(frm[0], WME_PARAM_ACM);
        wmep->wmep_aifsn = MS(frm[0], WME_PARAM_AIFSN);
        wmep->wmep_logcwmin = MS(frm[1], WME_PARAM_LOGCWMIN);
        wmep->wmep_logcwmax = MS(frm[1], WME_PARAM_LOGCWMAX);
        wmep->wmep_txopLimit = LE_READ_2(frm+2);
        frm += 4;
    }
    wme->wme_wmeChanParams.cap_info = *qosinfo;

    return 1;
#undef MS
}

int
ieee80211_parse_wmeinfo(struct ieee80211vap *vap, u_int8_t *frm,
                        u_int8_t *qosinfo)
{
    struct ieee80211_wme_state *wme = &vap->iv_ic->ic_wme;
    u_int len = frm[1], qosinfo_count;

    *qosinfo = 0;

    if (len < sizeof(struct ieee80211_ie_wme) - 2) {
        /* XXX: TODO msg+stats */
        return -1;
    }

    *qosinfo = frm[__offsetof(struct ieee80211_wme_param, param_qosInfo)];
    qosinfo_count = *qosinfo & WME_QOSINFO_COUNT;

    /* XXX do proper check for wraparound */
    if (qosinfo_count == (wme->wme_wmeChanParams.cap_info & WME_QOSINFO_COUNT))
        return 0;

    wme->wme_wmeChanParams.cap_info = *qosinfo;

    return 1;
}

int
ieee80211_parse_tspecparams(struct ieee80211vap *vap, u_int8_t *frm)
{
    struct ieee80211_tsinfo_bitmap *tsinfo;

    tsinfo = (struct ieee80211_tsinfo_bitmap *) &((struct ieee80211_wme_tspec *) frm)->ts_tsinfo[0];

    if (tsinfo->tid == 6)
        OS_MEMCPY(&vap->iv_ic->ic_sigtspec, frm, sizeof(struct ieee80211_wme_tspec));
    else
        OS_MEMCPY(&vap->iv_ic->ic_datatspec, frm, sizeof(struct ieee80211_wme_tspec));

    return 1;
}

/*
 * used by STA when it receives a (RE)ASSOC rsp.
 */
int
ieee80211_parse_timeieparams(struct ieee80211vap *vap, u_int8_t *frm)
{
    struct ieee80211_ie_timeout_interval *tieinfo;

    tieinfo = (struct ieee80211_ie_timeout_interval *) frm;

    if (tieinfo->interval_type == IEEE80211_TIE_INTERVAL_TYPE_ASSOC_COMEBACK_TIME)
        vap->iv_assoc_comeback_time = tieinfo->value;
    else
        vap->iv_assoc_comeback_time = 0;

    return 1;
}

/*
 * used by HOST AP when it receives a (RE)ASSOC req.
 */
int
ieee80211_parse_wmeie(u_int8_t *frm, const struct ieee80211_frame *wh,
                      struct ieee80211_node *ni)
{
    u_int len = frm[1];
    u_int8_t ac;

    if (len != 7) {
        IEEE80211_DISCARD_IE(ni->ni_vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WME,
            "WME IE", "too short, len %u", len);
        return -1;
    }
    ni->ni_uapsd = frm[WME_CAPINFO_IE_OFFSET];
    if (ni->ni_uapsd) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_UAPSD);
        switch (WME_UAPSD_MAXSP(ni->ni_uapsd)) {
        case 1:
            ni->ni_uapsd_maxsp = 2;
            break;
        case 2:
            ni->ni_uapsd_maxsp = 4;
            break;
        case 3:
            ni->ni_uapsd_maxsp = 6;
            break;
        default:
            ni->ni_uapsd_maxsp = WME_UAPSD_NODE_MAXQDEPTH;
        }
        for (ac = 0; ac < WME_NUM_AC; ac++) {
            ni->ni_uapsd_ac_trigena[ac] = (WME_UAPSD_AC_ENABLED(ac, ni->ni_uapsd)) ? 1:0;
            ni->ni_uapsd_ac_delivena[ac] = (WME_UAPSD_AC_ENABLED(ac, ni->ni_uapsd)) ? 1:0;
        }
    } else {
        ieee80211node_clear_flag(ni, IEEE80211_NODE_UAPSD);
    }

    IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_POWER, ni,
        "UAPSD bit settings from STA: %02x", ni->ni_uapsd);

    return 1;
}

/*
 * Convert a WPA cipher selector OUI to an internal
 * cipher algorithm.  Where appropriate we also
 * record any key length.
 */
static int
wpa_cipher(u_int8_t *sel, u_int8_t *keylen)
{
    u_int32_t w = LE_READ_4(sel);

    switch (w)
    {
    case WPA_SEL(WPA_CSE_NULL):
        return IEEE80211_CIPHER_NONE;
    case WPA_SEL(WPA_CSE_WEP40):
        if (keylen)
            *keylen = 40 / NBBY;
        return IEEE80211_CIPHER_WEP;
    case WPA_SEL(WPA_CSE_WEP104):
        if (keylen)
            *keylen = 104 / NBBY;
        return IEEE80211_CIPHER_WEP;
    case WPA_SEL(WPA_CSE_TKIP):
        return IEEE80211_CIPHER_TKIP;
    case WPA_SEL(WPA_CSE_CCMP):
        return IEEE80211_CIPHER_AES_CCM;
    }
    return 32;      /* NB: so 1<< is discarded */
}

/*
 * Convert a WPA key management/authentication algorithm
 * to an internal code.
 */
static int
wpa_keymgmt(u_int8_t *sel)
{
    u_int32_t w = LE_READ_4(sel);

    switch (w)
    {
    case WPA_SEL(WPA_ASE_8021X_UNSPEC):
        return WPA_ASE_8021X_UNSPEC;
    case WPA_SEL(WPA_ASE_8021X_PSK):
        return WPA_ASE_8021X_PSK;
    case WPA_SEL(WPA_ASE_NONE):
        return WPA_ASE_NONE;
    case CCKM_SEL(CCKM_ASE_UNSPEC):
        return WPA_CCKM_AKM;
    }
    return 0;       /* NB: so is discarded */
}

/*
 * Parse a WPA information element to collect parameters
 * and validate the parameters against what has been
 * configured for the system.
 */
int
ieee80211_parse_wpa(struct ieee80211vap *vap, u_int8_t *frm,
                    struct ieee80211_rsnparms *rsn)
{
    u_int8_t len = frm[1];
    u_int32_t w;
    int n;

    /*
     * Check the length once for fixed parts: OUI, type,
     * version, mcast cipher, and 2 selector counts.
     * Other, variable-length data, must be checked separately.
     */
    RSN_RESET_AUTHMODE(rsn);
    RSN_SET_AUTHMODE(rsn, IEEE80211_AUTH_WPA);

    if (len < 14) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "WPA", "too short, len %u", len);
        return IEEE80211_REASON_IE_INVALID;
    }
    frm += 6, len -= 4;     /* NB: len is payload only */
    /* NB: iswapoui already validated the OUI and type */
    w = LE_READ_2(frm);
    if (w != WPA_VERSION) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "WPA", "bad version %u", w);
        return IEEE80211_REASON_IE_INVALID;
    }
    frm += 2, len -= 2;

    /* multicast/group cipher */
    RSN_RESET_MCAST_CIPHERS(rsn);
    w = wpa_cipher(frm, &rsn->rsn_mcastkeylen);
    RSN_SET_MCAST_CIPHER(rsn, w);
    frm += 4, len -= 4;

    /* unicast ciphers */
    n = LE_READ_2(frm);
    frm += 2, len -= 2;
    if (len < n*4+2) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "WPA", "ucast cipher data too short; len %u, n %u",
            len, n);
        return IEEE80211_REASON_IE_INVALID;
    }

    RSN_RESET_UCAST_CIPHERS(rsn);
    for (; n > 0; n--) {
        RSN_SET_UCAST_CIPHER(rsn, wpa_cipher(frm, &rsn->rsn_ucastkeylen));
        frm += 4, len -= 4;
    }

    if (rsn->rsn_ucastcipherset == 0) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "WPA", "%s", "ucast cipher set empty");
        return IEEE80211_REASON_IE_INVALID;
    }

    /* key management algorithms */
    n = LE_READ_2(frm);
    frm += 2, len -= 2;
    if (len < n*4) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "WPA", "key mgmt alg data too short; len %u, n %u",
            len, n);
        return IEEE80211_REASON_IE_INVALID;
    }
    w = 0;
    rsn->rsn_keymgmtset = 0;
    for (; n > 0; n--) {
        w = wpa_keymgmt(frm);
        if (w == WPA_CCKM_AKM) { /* CCKM AKM */
            RSN_SET_AUTHMODE(rsn, IEEE80211_AUTH_CCKM);
            // when AuthMode is CCKM we don't need keymgmtset
            // as AuthMode drives the AKM_CCKM in WPA/RSNIE
            //rsn->rsn_keymgmtset |= 0;
        }
        else
            rsn->rsn_keymgmtset |= (w&0xff);
        frm += 4, len -= 4;
    }

    /* optional capabilities */
    if (len >= 2) {
        rsn->rsn_caps = LE_READ_2(frm);
        frm += 2, len -= 2;
    }

    return 0;
}

/*
 * Convert an RSN cipher selector OUI to an internal
 * cipher algorithm.  Where appropriate we also
 * record any key length.
 */
static int
rsn_cipher(u_int8_t *sel, u_int8_t *keylen)
{
#define RSN_SEL(x)  (((x)<<24)|RSN_OUI)
    u_int32_t w = LE_READ_4(sel);

    switch (w)
    {
    case RSN_SEL(RSN_CSE_NULL):
        return IEEE80211_CIPHER_NONE;
    case RSN_SEL(RSN_CSE_WEP40):
        if (keylen)
            *keylen = 40 / NBBY;
        return IEEE80211_CIPHER_WEP;
    case RSN_SEL(RSN_CSE_WEP104):
        if (keylen)
            *keylen = 104 / NBBY;
        return IEEE80211_CIPHER_WEP;
    case RSN_SEL(RSN_CSE_TKIP):
        return IEEE80211_CIPHER_TKIP;
    case RSN_SEL(RSN_CSE_CCMP):
        return IEEE80211_CIPHER_AES_CCM;
    case RSN_SEL(RSN_CSE_CCMP_256):
        return IEEE80211_CIPHER_AES_CCM_256;
    case RSN_SEL(RSN_CSE_GCMP_128):
        return IEEE80211_CIPHER_AES_GCM;
    case RSN_SEL(RSN_CSE_GCMP_256):
        return IEEE80211_CIPHER_AES_GCM_256;
    case RSN_SEL(RSN_CSE_WRAP):
        return IEEE80211_CIPHER_AES_OCB;
    case RSN_SEL(RSN_CSE_AES_CMAC):
        return IEEE80211_CIPHER_AES_CMAC;
    case RSN_SEL(RSN_CSE_BIP_GMAC_128):
        return IEEE80211_CIPHER_AES_GMAC;
    case RSN_SEL(RSN_CSE_BIP_GMAC_256):
        return IEEE80211_CIPHER_AES_GMAC_256;
    case RSN_SEL(RSN_CSE_BIP_CMAC_256):
        return IEEE80211_CIPHER_AES_CMAC_256;
    }
    return 32;      /* NB: so 1<< is discarded */
#undef RSN_SEL
}

/*
 * Convert an RSN key management/authentication algorithm
 * to an internal code.
 */
static int
rsn_keymgmt(u_int8_t *sel)
{
#define RSN_SEL(x)  (((x)<<24)|RSN_OUI)
    u_int32_t w = LE_READ_4(sel);

    switch (w)
    {
    case RSN_SEL(RSN_ASE_8021X_UNSPEC):
        return RSN_ASE_8021X_UNSPEC;
    case RSN_SEL(RSN_ASE_8021X_PSK):
        return RSN_ASE_8021X_PSK;
    case RSN_SEL(RSN_ASE_NONE):
        return RSN_ASE_NONE;
    case RSN_SEL(AKM_SUITE_TYPE_SHA256_IEEE8021X):
        return RSN_ASE_SHA256_IEEE8021X;
    case RSN_SEL(AKM_SUITE_TYPE_SHA256_PSK):
        return RSN_ASE_SHA256_PSK;
    case CCKM_SEL(CCKM_ASE_UNSPEC):
        return RSN_CCKM_AKM;
    case RSN_SEL(AKM_SUITE_TYPE_FT_IEEE8021X):
        return RSN_ASE_FT_IEEE8021X;
    case RSN_SEL(AKM_SUITE_TYPE_FT_PSK):
        return RSN_ASE_FT_PSK;
    }
    return 0;       /* NB: so is discarded */
#undef RSN_SEL
}

/*
 * Parse a WPA/RSN information element to collect parameters
 * and validate the parameters against what has been
 * configured for the system.
 */
int
ieee80211_parse_rsn(struct ieee80211vap *vap, u_int8_t *frm,
                    struct ieee80211_rsnparms *rsn)
{
    u_int8_t len = frm[1];
    u_int32_t w;
    int n;

    /*
    * Check the length once for fixed parts:
    * version, mcast cipher, and 2 selector counts.
    * Other, variable-length data, must be checked separately.
    */
    RSN_RESET_AUTHMODE(rsn);
    RSN_SET_AUTHMODE(rsn, IEEE80211_AUTH_RSNA);

    if (len < 10) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "RSN", "too short, len %u", len);
        return IEEE80211_REASON_IE_INVALID;
    }
    frm += 2;
    w = LE_READ_2(frm);
    if (w != RSN_VERSION) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "RSN", "bad version %u", w);
        return IEEE80211_REASON_IE_INVALID;
    }
    frm += 2, len -= 2;

    /* multicast/group cipher */
    RSN_RESET_MCAST_CIPHERS(rsn);
    w = rsn_cipher(frm, &rsn->rsn_mcastkeylen);
    RSN_SET_MCAST_CIPHER(rsn, w);
    frm += 4, len -= 4;

    /* unicast ciphers */
    n = LE_READ_2(frm);
    frm += 2, len -= 2;
    if (len < n*4+2) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "RSN", "ucast cipher data too short; len %u, n %u",
            len, n);
        return IEEE80211_REASON_IE_INVALID;
    }

    RSN_RESET_UCAST_CIPHERS(rsn);
    for (; n > 0; n--) {
        RSN_SET_UCAST_CIPHER(rsn, rsn_cipher(frm, &rsn->rsn_ucastkeylen));
        frm += 4, len -= 4;
    }

    if (rsn->rsn_ucastcipherset == 0) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "RSN", "%s", "ucast cipher set empty");
        return IEEE80211_REASON_IE_INVALID;
    }

    /* key management algorithms */
    n = LE_READ_2(frm);
    frm += 2, len -= 2;
    if (len < n*4) {
        IEEE80211_DISCARD_IE(vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
            "RSN", "key mgmt alg data too short; len %u, n %u",
            len, n);
        return IEEE80211_REASON_IE_INVALID;
    }
    w = 0;
    rsn->rsn_keymgmtset = 0;
    for (; n > 0; n--) {
        w = rsn_keymgmt(frm);
        if (w == RSN_CCKM_AKM) { /* CCKM AKM */
            RSN_SET_AUTHMODE(rsn, IEEE80211_AUTH_CCKM);
            // when AuthMode is CCKM we don't need keymgmtset
            // as AuthMode drives the AKM_CCKM in WPA/RSNIE
            //rsn->rsn_keymgmtset |= 0;
        }
        else {
            rsn->rsn_keymgmtset |= w;
        }
        frm += 4, len -= 4;
    }

    /* optional RSN capabilities */
    if (len >= 2) {
        rsn->rsn_caps = LE_READ_2(frm);
        frm += 2, len -= 2;
        if((rsn->rsn_caps & RSN_CAP_MFP_ENABLED) || (rsn->rsn_caps & RSN_CAP_MFP_REQUIRED)){
            RSN_RESET_MCASTMGMT_CIPHERS(rsn);
            w = IEEE80211_CIPHER_AES_CMAC;
            RSN_SET_MCASTMGMT_CIPHER(rsn, w);
        }
    }

    /* optional XXXPMKID */
    if (len >= 2) {
        n = LE_READ_2(frm);
        frm += 2, len -= 2;
        /* Skip them */
        if (len < n*16) {
            IEEE80211_DISCARD_IE(vap,
                IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
                "RSN", "key mgmt OMKID data too short; len %u, n %u",
                len, n);
            return IEEE80211_REASON_IE_INVALID;
        }
        frm += n * 16, len -= n * 16;
    }

    /* optional multicast/group management frame cipher */
    if (len >= 4) {
        RSN_RESET_MCASTMGMT_CIPHERS(rsn);
        w = rsn_cipher(frm, NULL);
        if((w != IEEE80211_CIPHER_AES_CMAC)
           && (w != IEEE80211_CIPHER_AES_CMAC_256)
           && (w != IEEE80211_CIPHER_AES_GMAC)
           && (w != IEEE80211_CIPHER_AES_GMAC_256) ){
            IEEE80211_DISCARD_IE(vap,
                IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
                "RSN", "invalid multicast/group management frame cipher; len %u, n %u",
                len, n);
            return IEEE80211_REASON_IE_INVALID;
        }
        RSN_SET_MCASTMGMT_CIPHER(rsn, w);
        frm += 4, len -= 4;
    }

    return IEEE80211_STATUS_SUCCESS;
}

void
ieee80211_savenie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie, u_int ielen)
{
    /*
    * Record information element for later use.
    */
    if (*iep == NULL || (*iep)[1] != ie[1])
    {
        if (*iep != NULL)
            OS_FREE(*iep);
		*iep = (void *) OS_MALLOC(osdev, ielen, GFP_KERNEL);
    }
    if (*iep != NULL)
        OS_MEMCPY(*iep, ie, ielen);
}

void
ieee80211_saveie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie)
{
    u_int ielen = ie[1]+2;
    ieee80211_savenie(osdev,iep, ie, ielen);
}

void
ieee80211_process_athextcap_ie(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_ath_extcap *athextcapIe =
        (struct ieee80211_ie_ath_extcap *) ie;
    u_int16_t remote_extcap = athextcapIe->ath_extcap_extcap;

    remote_extcap = LE_READ_2(&remote_extcap);

    /* We know remote node is an Atheros Owl or follow-on device */
    ni->ni_flags |= IEEE80211_NODE_ATH;

    /* If either one of us is capable of OWL WDS workaround,
     * implement WDS mode block-ack corruption workaround
     */
    if (remote_extcap & IEEE80211_ATHEC_OWLWDSWAR) {
        ni->ni_flags |= IEEE80211_NODE_OWL_WDSWAR;
    }

    /* If device and remote node support the Atheros proprietary
     * wep/tkip aggregation mode, mark node as supporting
     * wep/tkip w/aggregation.
     * Save off the number of rx delimiters required by the destination to
     * properly receive tkip/wep with aggregation.
     */
    if (remote_extcap & IEEE80211_ATHEC_WEPTKIPAGGR) {
        ni->ni_flags |= IEEE80211_NODE_WEPTKIPAGGR;
        ni->ni_weptkipaggr_rxdelim = athextcapIe->ath_extcap_weptkipaggr_rxdelim;
    }
    /* Check if remote device, require extra delimiters to be added while
     * sending aggregates. Osprey 1.0 and earlier chips need this.
     */
    if (remote_extcap & IEEE80211_ATHEC_EXTRADELIMWAR) {
        ni->ni_flags |= IEEE80211_NODE_EXTRADELIMWAR;
    }

}

void
ieee80211_process_whc_rept_info_ie(struct ieee80211_node *ni, const u_int8_t *ie)
{
    struct ieee80211vap *vap = ni->ni_vap;
    const struct ieee80211_ie_whc_rept_info *whcReptInfoIE =
                    (const struct ieee80211_ie_whc_rept_info *)ie;

    if (whcReptInfoIE->whc_rept_info_len < 6) {
        IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID, "WHC Rept Info",
                             "too short, len %u", whcReptInfoIE->whc_rept_info_len);
        return;
    }

    if (whcReptInfoIE->whc_rept_info_version != QCA_OUI_WHC_REPT_INFO_VERSION) {
        IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID, "WHC Rept Info",
                             "unexpected version %u",
                             whcReptInfoIE->whc_rept_info_version);
        return;
    }

    ieee80211node_set_whc_rept_info(ni);
}

void
ieee80211_process_whc_apinfo_ie(struct ieee80211_node *ni, const u_int8_t *ie)
{
    struct ieee80211vap *vap = ni->ni_vap;
    const struct ieee80211_ie_whc_apinfo *whcAPInfoIE =
            (const struct ieee80211_ie_whc_apinfo *) ie;
    u_int16_t whcCaps;

    /* Unfortunately we cannot derive the expected length from the IE without
     * having to also account for padding. Hence, the hard coded value here.
     */
    if (whcAPInfoIE->whc_apinfo_len < 9) {
        IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID, "WHC AP Info",
                             "too short, len %u", whcAPInfoIE->whc_apinfo_len);
        return;
    }

    if (whcAPInfoIE->whc_apinfo_version != QCA_OUI_WHC_AP_INFO_VERSION) {
        IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID, "WHC AP Info",
                             "unexpected version %u",
                             whcAPInfoIE->whc_apinfo_version);
        return;
    }

    whcCaps = LE_READ_2(&whcAPInfoIE->whc_apinfo_capabilities);
    if (whcCaps & QCA_OUI_WHC_AP_INFO_CAP_WDS) {
        ieee80211node_set_whc_apinfo_flag(ni, IEEE80211_NODE_WHC_APINFO_WDS);
    }

    if (whcCaps & QCA_OUI_WHC_AP_INFO_CAP_SON) {
        ieee80211node_set_whc_apinfo_flag(ni, IEEE80211_NODE_WHC_APINFO_SON);
    }

    /* The + 1 sets up this node so that it advertises the right hop count
     * for anybody that tries to associate to it.
     */
    if(whcAPInfoIE->whc_apinfo_root_ap_dist == WHC_INVALID_ROOT_AP_DISTANCE)
        vap->iv_whc_root_ap_distance = WHC_INVALID_ROOT_AP_DISTANCE;
    else
        vap->iv_whc_root_ap_distance = whcAPInfoIE->whc_apinfo_root_ap_dist + 1;
}

void
ieee80211_parse_athParams(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_ie_athAdvCap *athIe =
            (struct ieee80211_ie_athAdvCap *) ie;

    (void)vap;
    (void)ic;

    ni->ni_ath_flags = athIe->athAdvCap_capability;
    if (ni->ni_ath_flags & IEEE80211_ATHC_COMP)
        ni->ni_ath_defkeyindex = LE_READ_2(&athIe->athAdvCap_defKeyIndex);
}

/*support for WAPI: parse WAPI IE*/
#if ATH_SUPPORT_WAPI
/*
 * Convert an WAPI cipher selector OUI to an internal
 * cipher algorithm.  Where appropriate we also
 * record any key length.
 */
static int
wapi_cipher(u_int8_t *sel, u_int8_t *keylen)
{
#define	WAPI_SEL(x)	(((x)<<24)|WAPI_OUI)
	u_int32_t w = LE_READ_4(sel);

	switch (w) {
	case WAPI_SEL(RSN_CSE_NULL):
		return IEEE80211_CIPHER_NONE;
	case WAPI_SEL(WAPI_CSE_WPI_SMS4):
		if (keylen)
			*keylen = 128 / NBBY;
		return IEEE80211_CIPHER_WAPI;
	}
	return 32;		/* NB: so 1<< is discarded */
#undef WAPI_SEL
}

/*
 * Convert an RSN key management/authentication algorithm
 * to an internal code.
 */
static int
wapi_keymgmt(u_int8_t *sel)
{
#define	WAPI_SEL(x)	(((x)<<24)|WAPI_OUI)
	u_int32_t w = LE_READ_4(sel);

	switch (w) {
	case WAPI_SEL(WAPI_ASE_WAI_UNSPEC):
		return WAPI_ASE_WAI_UNSPEC;
	case WAPI_SEL(WAPI_ASE_WAI_PSK):
		return WAPI_ASE_WAI_PSK;
	case WAPI_SEL(WAPI_ASE_NONE):
		return WAPI_ASE_NONE;
	}
	return 0;		/* NB: so is discarded */
#undef WAPI_SEL
}

/*
 * Parse a WAPI information element to collect parameters
 * and validate the parameters against what has been
 * configured for the system.
 */
int
ieee80211_parse_wapi(struct ieee80211vap *vap, u_int8_t *frm,
	struct ieee80211_rsnparms *rsn)
{
	u_int8_t len = frm[1];
	u_int32_t w;
	int n;

	/*
	 * Check the length once for fixed parts:
	 * version, mcast cipher, and 2 selector counts.
	 * Other, variable-length data, must be checked separately.
	 */
    RSN_RESET_AUTHMODE(rsn);
    RSN_SET_AUTHMODE(rsn, IEEE80211_AUTH_WAPI);

	if (!ieee80211_vap_wapi_is_set(vap)) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "vap not WAPI, flags 0x%x", vap->iv_flags);
		return IEEE80211_REASON_IE_INVALID;
	}

	if (len < 20) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "too short, len %u", len);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2;
	w = LE_READ_2(frm);
	if (w != WAPI_VERSION) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "bad version %u", w);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2, len -= 2;

	/* key management algorithms */
	n = LE_READ_2(frm);
	frm += 2, len -= 2;
	if (len < n*4) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "key mgmt alg data too short; len %u, n %u",
		    len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= wapi_keymgmt(frm);
		frm += 4, len -= 4;
	}
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "%s", "no acceptable key mgmt alg");
		return IEEE80211_REASON_IE_INVALID;

	}
    rsn->rsn_keymgmtset = w & WAPI_ASE_WAI_AUTO;

	/* unicast ciphers */
	n = LE_READ_2(frm);
	frm += 2, len -= 2;
	if (len < n*4+2) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "ucast cipher data too short; len %u, n %u",
		    len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
    RSN_RESET_UCAST_CIPHERS(rsn);
	for (; n > 0; n--) {
		w |= 1<<wapi_cipher(frm, &rsn->rsn_ucastkeylen);
		frm += 4, len -= 4;
	}
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "%s", "ucast cipher set empty");
		return IEEE80211_REASON_IE_INVALID;
	}
	if (w & (1<<IEEE80211_CIPHER_WAPI)){
		RSN_SET_UCAST_CIPHER(rsn, IEEE80211_CIPHER_WAPI);}
	else{
		RSN_SET_UCAST_CIPHER(rsn, IEEE80211_CIPHER_WAPI);}

	/* multicast/group cipher */
    RSN_RESET_MCAST_CIPHERS(rsn);
	w = wapi_cipher(frm, &rsn->rsn_mcastkeylen);
    RSN_SET_MCAST_CIPHER(rsn, w);
	if (!RSN_HAS_MCAST_CIPHER(rsn, IEEE80211_CIPHER_WAPI)) {
		IEEE80211_DISCARD_IE(vap,
		    IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
		    "WAPI", "mcast cipher mismatch; got %u, expected %u",
		    w, IEEE80211_CIPHER_WAPI);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 4, len -= 4;


	/* optional RSN capabilities */
	if (len > 2)
		rsn->rsn_caps = LE_READ_2(frm);
	/* XXXPMKID */

	return 0;
}
#endif /*ATH_SUPPORT_WAPI*/

static int
ieee80211_query_ie(struct ieee80211vap *vap, u_int8_t *frm)
{
    switch (*frm) {
        case IEEE80211_ELEMID_RSN:
            if ((frm[1] + 2) < IEEE80211_RSN_IE_LEN) {
                return -EOVERFLOW;
            }
            ieee80211_setup_rsn_ie(vap, frm);
            break;
        default:
            break;
    }
    return EOK;
}

int
wlan_get_ie(wlan_if_t vaphandle, u_int8_t *frm)
{
    return ieee80211_query_ie(vaphandle, frm);
}

static int
ieee80211_parse_csa_ecsa_ie(
    u_int8_t * pucInfoBlob,
    u_int32_t uSizeOfBlob,
    u_int8_t ucInfoId,
    u_int8_t * pucLength,
    u_int8_t ** ppvInfoEle
    )
{
    int status = IEEE80211_STATUS_SUCCESS;
    struct ieee80211_ie_header * pInfoEleHdr = NULL;
    u_int32_t uRequiredSize = 0;
    bool bFound = FALSE;

    *pucLength = 0;
    *ppvInfoEle = NULL;
    while(uSizeOfBlob) {

        pInfoEleHdr = (struct ieee80211_ie_header *)pucInfoBlob;
        if (uSizeOfBlob < sizeof(struct ieee80211_ie_header)) {
            break;
        }

        uRequiredSize = (u_int32_t)(pInfoEleHdr->length) + sizeof(struct ieee80211_ie_header);
        if (uSizeOfBlob < uRequiredSize) {
            break;
        }

        if (pInfoEleHdr->element_id == ucInfoId) {
            *pucLength = pInfoEleHdr->length;
            *ppvInfoEle = pucInfoBlob + sizeof(struct ieee80211_ie_header);
            bFound = TRUE;
            break;
        }

        uSizeOfBlob -= uRequiredSize;
        pucInfoBlob += uRequiredSize;
    }

    if (!bFound) {
        status = IEEE80211_REASON_IE_INVALID;
    }
    return status;
}

struct ieee80211_channel *
ieee80211_get_new_sw_chan (
    struct ieee80211_node                       *ni,
    struct ieee80211_channelswitch_ie           *chanie,
    struct ieee80211_extendedchannelswitch_ie   *echanie,
    struct ieee80211_ie_sec_chan_offset         *secchanoffsetie,
    struct ieee80211_ie_wide_bw_switch         *widebwie,
    u_int8_t *cswarp
    )
{
    struct ieee80211_channel *chan;
    struct ieee80211com *ic = ni->ni_ic;
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
    u_int8_t    secchanoffset = 0;
    u_int8_t    newchannel = 0;
    u_int8_t    newcfreq2 = 0;
    enum ieee80211_cwm_width secoff_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_cwm_width wideband_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_cwm_width dest_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_cwm_width max_allowed_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_mode mode = IEEE80211_MODE_INVALID;

   if(chanie) {
        newchannel = chanie->newchannel;
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
            "%s: CSA new channel = %d\n",
             __func__, chanie->newchannel);
    } else if (echanie) {
        newchannel = echanie->newchannel;
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
            "%s: E-CSA new channel = %d\n",
             __func__, echanie->newchannel);
    }


   if(widebwie) {
        newcfreq2 = widebwie->new_ch_freq_seg2;
        wideband_chwidth = widebwie->new_ch_width;
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
            "%s: wide bandwidth changed new vht chwidth = %d"
            " cfreq1: %d, cfreq2: %d\n", __func__, widebwie->new_ch_width,
            widebwie->new_ch_freq_seg1, newcfreq2);
    }

    if(secchanoffsetie) {
        secchanoffset = secchanoffsetie->sec_chan_offset;
        if ((secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) ||
            (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB)) {
            secoff_chwidth = IEEE80211_CWM_WIDTH40;
        } else {
            secchanoffset = IEEE80211_SEC_CHAN_OFFSET_SCN;
            secoff_chwidth = IEEE80211_CWM_WIDTH20;
        }
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
                "%s: HT bandwidth changed new secondary channel offset = %d\n",
                __func__, secchanoffset);
    }

    /* Channel switch announcement can't be used to switch
     * between 11a/b/g/n/ac modes. Only channel and width can
     * be switched. So first find the current association
     * mode and then find channel width announced by AP and
     * mask it with maximum channel width allowed by user
     * configuration.
     * For finding a/b/g/n/ac.. modes, current operating
     * channel mode can be used.
     */

    /* Below algorithm is used to derive the best channel:
     * 1. Find current operating mode a/b/g/n/ac from current channel --> M.
     * 2. Find new channel width announced by AP --> W.
     * 3. Mask W with max user configured width and find desired chwidth--> X.
     * 4. Combine M and X to find new composite phymode --> C.
     * 5. Check composite phymode C is supported by device.
     * 6. If step 5 evaluates true, C is the destination composite phymode.
     * 7. If step 5 evaluates false, find a new composite phymode C from M and X/2.
     * 8. Repeat until a device supported phymode is found or all channel
          width combinations are exausted.
     * 9. Find the new channel with C, cfreq1 and cfreq2.
     */

    /* Find current mode */
    mode = ieee80211_get_mode(ic);
    if (mode == IEEE80211_MODE_INVALID) {
        /* No valid mode found. */
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,
            IEEE80211_MSG_SCANENTRY, "%s : Invalid current mode\n", __func__);
        return NULL;
    }

    /* Calculate destination channel width */
    if (widebwie) {
        switch (wideband_chwidth) {
            case IEEE80211_VHTOP_CHWIDTH_2040:
                {
                    /* Wide band IE is never present for 20MHz */
                    dest_chwidth = IEEE80211_CWM_WIDTH40;
                    break;
                }
            case IEEE80211_VHTOP_CHWIDTH_80:
                {
                    dest_chwidth = IEEE80211_CWM_WIDTH80;
                    break;
                }
            case IEEE80211_VHTOP_CHWIDTH_160:
                {
                    dest_chwidth = IEEE80211_CWM_WIDTH160;
                    break;
                }
            case IEEE80211_VHTOP_CHWIDTH_80_80:
                {
                    dest_chwidth = IEEE80211_CWM_WIDTH80_80;
                    break;
                }
            default:
                IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
                 "%s : Invalid wideband channel width %d specified\n",
                  __func__, wideband_chwidth);
                return NULL;
        }
    } else if (secchanoffsetie) {
        dest_chwidth = secoff_chwidth;
    }

    /* Find maximum allowed chwidth */
    max_allowed_chwidth = ieee80211_get_vap_max_chwidth(ni->ni_vap);
    if ((dest_chwidth == IEEE80211_CWM_WIDTH80_80) && (max_allowed_chwidth == IEEE80211_CWM_WIDTH160)) {
        dest_chwidth = IEEE80211_CWM_WIDTH80;
    } else if ((dest_chwidth == IEEE80211_CWM_WIDTH160) && (max_allowed_chwidth == IEEE80211_CWM_WIDTH80_80)) {
        dest_chwidth = IEEE80211_CWM_WIDTH160;
    } else if (dest_chwidth > max_allowed_chwidth) {
        dest_chwidth = max_allowed_chwidth;
    }

    /* 11N mode is supported on both 5G and 2.4G bands.
     * Find which band AP is going to.
     */
     if (mode == IEEE80211_MODE_N) {
         if (newchannel > 20) {
             mode = IEEE80211_MODE_NA;
         } else {
             mode = IEEE80211_MODE_NG;
         }
    }

    do {
        /* Calculate destination composite Phymode and ensure device support */
        phymode = ieee80211_get_composite_phymode(mode, dest_chwidth, secchanoffset);
        if (phymode == IEEE80211_MODE_AUTO) {
            /* Could not find valid destination Phymode. */
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
            "%s : Could not find valid destination Phymode for mode: %d "
            "dest_chwidth: %d, secchanoffset: %d\n",__func__, mode, dest_chwidth,
            secchanoffset);
            return NULL;
        }
        if (IEEE80211_SUPPORT_PHY_MODE(ic, phymode)) {
            break;
        } else {
            /* If composite phymode is not supported by device,
             * try finding next composite phymode having lower chwidth
             */
            if ((dest_chwidth == IEEE80211_CWM_WIDTH160) ||
                (dest_chwidth == IEEE80211_CWM_WIDTH80_80)) {
                dest_chwidth = IEEE80211_CWM_WIDTH80;
            } else {
                dest_chwidth -= 1;
            }
        }
    } while (dest_chwidth >= IEEE80211_CWM_WIDTH20);

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
    "%s : New composite phymode is: %d", __func__, phymode);

    chan  =  ieee80211_find_dot11_channel(ic, newchannel, newcfreq2, phymode);

    if (!chan) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
                "%s : Couldn't find new channel with phymode: %d, "
                "newchannel: %d, newcfreq2: %d\n", __func__, phymode,
                newchannel, newcfreq2);
        return chan;
    }

    return chan;
}

/* Process CSA/ECSA IE and switch to new announced channel */
int
ieee80211_process_csa_ecsa_ie (
    struct ieee80211_node *ni,
   struct ieee80211_action * pia
    )
{
    struct ieee80211_extendedchannelswitch_ie * pecsaIe = NULL;
    struct ieee80211_channelswitch_ie * pcsaIe = NULL;
    struct ieee80211_ie_sec_chan_offset *psecchanoffsetIe = NULL;
    struct ieee80211_ie_wide_bw_switch  *pwidebwie = NULL;
    u_int8_t *cswarp = NULL;


    struct ieee80211vap *vap = ni->ni_vap;
     struct ieee80211com *ic = ni->ni_ic;

    struct ieee80211_channel* chan = NULL;

    u_int8_t * ptmp1 = NULL;
    u_int8_t * ptmp2 = NULL;
    u_int8_t size;
    int      err = (-EINVAL);

    ASSERT(pia);

    if(!(ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS)){
        return EOK;
        /*Returning EOK to make sure that we dont get disconnect from AP */
    }
    ptmp1 = (u_int8_t *)pia+sizeof(struct ieee80211_action);

    /*Find CSA/ECSA IE*/
    if (ieee80211_parse_csa_ecsa_ie((u_int8_t *)ptmp1,
                        sizeof(struct ieee80211_channelswitch_ie),
                        IEEE80211_ELEMID_CHANSWITCHANN,
                        &size,
                        (u_int8_t **)&ptmp2) == IEEE80211_STATUS_SUCCESS)
    {
           ptmp2 -= sizeof(struct ieee80211_ie_header);
           pcsaIe = (struct ieee80211_channelswitch_ie * )ptmp2 ;
    }

    if (ieee80211_parse_csa_ecsa_ie((u_int8_t *)ptmp1,
                        sizeof(struct ieee80211_extendedchannelswitch_ie),
                        IEEE80211_ELEMID_EXTCHANSWITCHANN,
                        &size,
                        (u_int8_t **)&ptmp2) == IEEE80211_STATUS_SUCCESS)
    {
        ptmp2 -= sizeof(struct ieee80211_ie_header);
        pecsaIe = (struct ieee80211_extendedchannelswitch_ie * )ptmp2 ;
    }

    if (ieee80211_parse_csa_ecsa_ie((u_int8_t *)ptmp1,
                        sizeof(struct ieee80211_ie_sec_chan_offset),
                        IEEE80211_ELEMID_SECCHANOFFSET,
                        &size,
                        (u_int8_t **)&ptmp2) == IEEE80211_STATUS_SUCCESS)
    {
        ptmp2 -= sizeof(struct ieee80211_ie_header);
        psecchanoffsetIe = (struct ieee80211_ie_sec_chan_offset * )ptmp2 ;
    }

    if (ieee80211_parse_csa_ecsa_ie((u_int8_t *)ptmp1,
                        sizeof(struct ieee80211_ie_wide_bw_switch),
                        IEEE80211_ELEMID_WIDE_BAND_CHAN_SWITCH,
                        &size,
                        (u_int8_t **)&ptmp2) == IEEE80211_STATUS_SUCCESS)
    {
        ptmp2 -= sizeof(struct ieee80211_channelswitch_ie);
        pwidebwie = (struct ieee80211_ie_wide_bw_switch * )ptmp2 ;
    }

    chan = ieee80211_get_new_sw_chan (ni, pcsaIe, pecsaIe, psecchanoffsetIe, pwidebwie, cswarp);

    if(!chan)
        return EOK;

     /*
     * Set or clear flag indicating reception of channel switch announcement
     * in this channel. This flag should be set before notifying the scan
     * algorithm.
     * We should not send probe requests on a channel on which CSA was
     * received until we receive another beacon without the said flag.
     */
    if ((pcsaIe != NULL) || (pecsaIe != NULL)) {
        ic->ic_curchan->ic_flagext |= IEEE80211_CHAN_CSA_RECEIVED;
    }

#if ATH_SUPPORT_IBSS_DFS
    /* only support pcsaIe for now */
    if (vap->iv_opmode == IEEE80211_M_IBSS &&
        chan &&
        pcsaIe) {

        if(ieee80211_dfs_action(vap, pcsaIe)) {
            err = EOK;
        }

    } else if (chan && (pcsaIe || pecsaIe)) {
#else
    if (chan && (pcsaIe || pecsaIe)) {
#endif /* ATH_SUPPORT_IBSS_DFS */
        /*
         * For Station, just switch channel right away.
         */
        if (!IEEE80211_IS_CHAN_SWITCH_STARTED(ic) &&
            (chan != vap->iv_bsschan))
        {
            IEEE80211_CHAN_SWITCH_START(ic);
            if (pcsaIe)
                    ni->ni_chanswitch_tbtt = pcsaIe->tbttcount;
            else if (pecsaIe)
                    ni->ni_chanswitch_tbtt = pecsaIe->tbttcount;

                    /*
             * Issue a channel switch request to resource manager.
             * If the function returns EOK (0) then its ok to change the channel synchronously
             * If the function returns EBUSY then resource manager will
             * switch channel asynchronously and post an event event handler registred by vap and
             * vap handler will inturn do the rest of the processing involved.
                     */
            err = ieee80211_resmgr_request_chanswitch(ic->ic_resmgr, vap, chan, MLME_REQ_ID);

            if (err == EOK) {
                err = ieee80211_set_channel(ic, chan);

                ieee80211_mlme_chanswitch_continue(ni, err);
            } else if (err == EBUSY) {
                err = EOK;
            }
        }
    }
    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: Exited.\n",__func__
                   );

    return err;
}

#if ATH_SUPPORT_IBSS_DFS

static int
ieee80211_validate_ie(
    u_int8_t * pucInfoBlob,
    u_int32_t uSizeOfBlob,
    u_int8_t ucInfoId,
    u_int8_t * pucLength,
    u_int8_t ** ppvInfoEle
    )
{
    int status = IEEE80211_STATUS_SUCCESS;
    struct ieee80211_ie_header * pInfoEleHdr = NULL;
    u_int32_t uRequiredSize = 0;
    bool bFound = FALSE;

    *pucLength = 0;
    *ppvInfoEle = NULL;
    while(uSizeOfBlob) {

        pInfoEleHdr = (struct ieee80211_ie_header *)pucInfoBlob;
        if (uSizeOfBlob < sizeof(struct ieee80211_ie_header)) {
            break;
        }

        uRequiredSize = (u_int32_t)(pInfoEleHdr->length) + sizeof(struct ieee80211_ie_header);
        if (uSizeOfBlob < uRequiredSize) {
            break;
        }

        if (pInfoEleHdr->element_id == ucInfoId) {
            *pucLength = pInfoEleHdr->length;
            *ppvInfoEle = pucInfoBlob + sizeof(struct ieee80211_ie_header);
            bFound = TRUE;
            break;
        }

        uSizeOfBlob -= uRequiredSize;
        pucInfoBlob += uRequiredSize;
    }

    if (!bFound) {
        status = IEEE80211_REASON_IE_INVALID;
    }
    return status;
}

/*
 * when we enter this function, we assume:
 * 1. if pmeasrepie is NULL, we build a measurement report with map field's radar set to 1
 * 2. if pmeasrepie is not NULL, only job is to repeat it.
 * 3. only basic report is used for now. For future expantion, it should be modified.
 *
 */
int
ieee80211_measurement_report_action (
    struct ieee80211vap                    *vap,
    struct ieee80211_measurement_report_ie *pmeasrepie
    )
{
    struct ieee80211_action_mgt_args       *actionargs;
    struct ieee80211_measurement_report_ie *newmeasrepie;
    struct ieee80211_measurement_report_basic_report *pbasic_report;
    struct ieee80211com *ic = vap->iv_ic;

    /* currently we only support IBSS mode */
    if (vap->iv_opmode != IEEE80211_M_IBSS) {
        return -EINVAL;
    }

    if(vap->iv_measrep_action_count_per_tbtt > vap->iv_ibss_dfs_csa_measrep_limit) {
        return EOK;
    }
    vap->iv_measrep_action_count_per_tbtt++;

    actionargs = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_action_mgt_args) , GFP_KERNEL);
    if (actionargs == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc arg buf. Size=%d\n",
                                    __func__, sizeof(struct ieee80211_action_mgt_args));
        return -EINVAL;
    }
    OS_MEMZERO(actionargs, sizeof(struct ieee80211_action_mgt_args));


    if (pmeasrepie) {

        actionargs->category = IEEE80211_ACTION_CAT_SPECTRUM;
        actionargs->action   = IEEE80211_ACTION_MEAS_REPORT;
        actionargs->arg1     = 0;   /* Dialog Token */
        actionargs->arg2     = 0;   /* not used */
        actionargs->arg3     = 0;   /* not used */
        actionargs->arg4     = (u_int8_t *)pmeasrepie;
        ieee80211_send_action(vap->iv_bss, actionargs, NULL);
    } else {

        newmeasrepie = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_measurement_report_ie) , GFP_KERNEL);
        if (newmeasrepie == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc report ie buf. Size=%d\n",
                                        __func__, sizeof(struct ieee80211_measurement_report_ie));
            OS_FREE(actionargs);
            return -EINVAL;
        }
        OS_MEMZERO(newmeasrepie, sizeof(struct ieee80211_measurement_report_ie));
        newmeasrepie->ie = IEEE80211_ELEMID_MEASREP;
        newmeasrepie->len = sizeof(struct ieee80211_measurement_report_ie)- sizeof(struct ieee80211_ie_header); /* might be different if other report type is supported */
        newmeasrepie->measurement_token = 0;
        newmeasrepie->measurement_report_mode = 0;
        newmeasrepie->measurement_type = 0;
        pbasic_report = (struct ieee80211_measurement_report_basic_report *)newmeasrepie->pmeasurement_report;

        pbasic_report->channel = ic->ic_curchan->ic_ieee;
        pbasic_report->measurement_start_time = vap->iv_bss->ni_tstamp.tsf; /* just make one */
        pbasic_report->measurement_duration = 50; /* fake */
        pbasic_report->map.radar = 1;
        pbasic_report->map.unmeasured = 0;

        actionargs->category = IEEE80211_ACTION_CAT_SPECTRUM;
        actionargs->action   = IEEE80211_ACTION_MEAS_REPORT;
        actionargs->arg1     = 0;   /* Dialog Token */
        actionargs->arg2     = 0;   /* not used */
        actionargs->arg3     = 0;   /* not used */
        actionargs->arg4     = (u_int8_t *)newmeasrepie;
        ieee80211_send_action(vap->iv_bss, actionargs, NULL);

        OS_FREE(newmeasrepie);
    }

    OS_FREE(actionargs);

    /* trigger beacon_update timer, we use it as timer */
    OS_DELAY(500);
    ieee80211_ibss_beacon_update_start(ic);

    return EOK;
}


/*  Process Measurement report and take action
 *  Currently this is only supported/tested in IBSS_DFS situation.
 *
 */

int
ieee80211_process_meas_report_ie (
    struct ieee80211_node *ni,
    struct ieee80211_action * pia
    )
{
    struct ieee80211_measurement_report_ie *pmeasrepie = NULL;
    struct ieee80211_measurement_report_basic_report *pbasic_report =NULL;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    u_int8_t * ptmp1 = NULL;
    u_int8_t * ptmp2 = NULL;
    u_int8_t size;
    int      err = (-EOK);
    u_int8_t i = 0;
    u_int8_t unit_len         = sizeof(struct channel_map_field);

    ASSERT(pia);

    if(!(ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS)) {
        return err;
    }
    ptmp1 = (u_int8_t *)pia + sizeof(struct ieee80211_action_measrep_header);

    /*Find measurement report IE*/
    if (ieee80211_validate_ie((u_int8_t *)ptmp1,
                        sizeof(struct ieee80211_measurement_report_ie),
                        IEEE80211_ELEMID_MEASREP,
                        &size,
                        (u_int8_t **)&ptmp2) == IEEE80211_STATUS_SUCCESS)
    {
           ptmp2 -= sizeof(struct ieee80211_ie_header);
           pmeasrepie = (struct ieee80211_measurement_report_ie * )ptmp2 ;
    } else {
        err = -EINVAL;
        return err;
    }

    if (vap->iv_opmode == IEEE80211_M_IBSS) {

        if(pmeasrepie->measurement_type == 0) { /* basic report */
            pbasic_report = (struct ieee80211_measurement_report_basic_report *)pmeasrepie->pmeasurement_report;
        } else {
            err = -EINVAL;
            return err;
        }

         /* mark currnet DFS element's channel's map field */
        for( i = (vap->iv_ibssdfs_ie_data.len - IBSS_DFS_ZERO_MAP_SIZE)/unit_len; i >0; i--) {
            if (vap->iv_ibssdfs_ie_data.ch_map_list[i-1].ch_num == pbasic_report->channel) {
                vap->iv_ibssdfs_ie_data.ch_map_list[i-1].chmap_in_byte |= pbasic_report->chmap_in_byte;
                vap->iv_ibssdfs_ie_data.ch_map_list[i-1].ch_map.unmeasured = 0;
                break;
            }
        }

        if(ic->ic_curchan->ic_ieee == pbasic_report->channel) {
            if (IEEE80211_ADDR_EQ(vap->iv_ibssdfs_ie_data.owner, vap->iv_myaddr) &&
                pbasic_report->map.radar) {
                ieee80211_dfs_action(vap, NULL);
            } else if (pbasic_report->map.radar) { /* Not owner, trigger recovery mode */
                if (vap->iv_ibssdfs_state == IEEE80211_IBSSDFS_JOINER) {
                    vap->iv_ibssdfs_state = IEEE80211_IBSSDFS_WAIT_RECOVERY;
                }
            }
        }
        /* repeat measurement report when we receive it */
        err = ieee80211_measurement_report_action(vap, pmeasrepie);
    }
    return err;
}
#endif /* ATH_SUPPORT_IBSS_DFS */


u_int8_t *
ieee80211_add_mmie(struct ieee80211vap *vap, u_int8_t *bfrm, u_int32_t len)
{
    struct ieee80211_key *key = &vap->iv_igtk_key;
    struct ieee80211_mmie *mmie;
    u_int8_t *pn, aad[20], *efrm, nounce[12];
    struct ieee80211_frame *wh;
    u_int32_t i, hdrlen;

    if (!key && !bfrm) {
        /* Invalid Key or frame */
        return NULL;
    }

    efrm = bfrm + len;
    len += sizeof(*mmie);
    hdrlen = sizeof(*wh);

    mmie = (struct ieee80211_mmie *) efrm;
    mmie->element_id = IEEE80211_ELEMID_MMIE;
    mmie->length = sizeof(*mmie) - 2;
    mmie->key_id = cpu_to_le16(key->wk_keyix);

    /* PN = PN + 1 */
    pn = (u_int8_t*)&key->wk_keytsc;

    for (i = 0; i <= 5; i++) {
        pn[i]++;
        if (pn[i])
            break;
    }

    /* Copy IPN */
    memcpy(mmie->sequence_number, pn, 6);

    wh = (struct ieee80211_frame *) bfrm;

    /* generate BIP AAD: FC(masked) || A1 || A2 || A3 */

    /* FC type/subtype */
    aad[0] = wh->i_fc[0];
    /* Mask FC Retry, PwrMgt, MoreData flags to zero */
    aad[1] = wh->i_fc[1] & ~(IEEE80211_FC1_RETRY | IEEE80211_FC1_PWR_MGT | IEEE80211_FC1_MORE_DATA);
    /* A1 || A2 || A3 */
    memcpy(aad + 2, wh->i_addr1, IEEE80211_ADDR_LEN);
    memcpy(aad + 8, wh->i_addr2, IEEE80211_ADDR_LEN);
    memcpy(aad + 14, wh->i_addr3, IEEE80211_ADDR_LEN);
    /*
     * MIC = AES-128-CMAC(IGTK, AAD || Management Frame Body || MMIE, 64)
     */

    if((RSN_CIPHER_IS_CMAC(&vap->iv_rsn)) || RSN_CIPHER_IS_CMAC256(&vap->iv_rsn)){
        /* size of MIC is 16 for GMAC, where size of mic for CMAC is 8 */
        len -= 8;
        mmie->length -= 8;
        ieee80211_cmac_calc_mic(key, aad, bfrm + hdrlen, len - hdrlen, mmie->mic);
    }else if((RSN_CIPHER_IS_GMAC(&vap->iv_rsn)) || RSN_CIPHER_IS_GMAC256(&vap->iv_rsn)){
        memcpy(nounce, wh->i_addr2, IEEE80211_ADDR_LEN);
        memcpy(nounce + 6, pn, 6);
        ieee80211_gmac_calc_mic(key, aad, bfrm + hdrlen, 20, mmie->mic,nounce);
    } else {
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s[%d] CMAC / GMAC Not a valid rsn  \n",__func__,__LINE__);
        return NULL;
    }

    return bfrm + len;

}

void
ieee80211_set_vht_rates(struct ieee80211com *ic, struct ieee80211vap  *vap)
{
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap),
             rx_streams = ieee80211_get_rxstreams(ic, vap);
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t bcc_11ng_256qam_20mhz_s = 0;

    bcc_11ng_256qam_20mhz_s = IEEE80211_IS_CHAN_11NG(ic->ic_curchan) &&
                                ieee80211_vap_256qam_is_set(vap) &&
                                (vap->iv_ldpc == IEEE80211_HTCAP_C_LDPC_NONE) &&
                                (ic_cw_width == IEEE80211_CWM_WIDTH20);
    /* Adjust supported rate set based on txchainmask */
    switch (tx_streams) {
        default:
            /* Default to single stream */
        case 1:
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !vap->iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_9; /* MCS 0-9 */
            }
            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS1_MASK);
            }
        break;

        case 2:
            /* Dual stream */
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !vap->iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_9; /* MCS 0-9 */
            }
            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS2_MASK);
            }
        break;

        case 3:
            /* Tri stream */
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS3_MCS0_9; /* MCS 0-9 */
            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS3_MASK);
            }
        break;
#if ATH_SUPPORT_4SS
        case 4:
        /* four stream */
             /*MCS9 is not supported for BCC, NSS=1,2,4 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !vap->iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_9; /* MCS 0-9 */
            }
            if (vap->iv_vht_tx_mcsmap) {
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS4_MASK);
            }
        break;
#endif
    } /* end switch */

    /* Adjust rx rates based on the rx chainmask */
    switch (rx_streams) {
        default:
            /* Default to single stream */
        case 1:
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !vap->iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_9;
            }
            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS1_MASK);
            }
        break;

        case 2:
            /* Dual stream */
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !vap->iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_9;
            }
            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS2_MASK);
            }
        break;

        case 3:
            /* Tri stream */
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS3_MCS0_9;
            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS3_MASK);
            }
        break;
#if ATH_SUPPORT_4SS
        case 4:
        /* four stream */
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !vap->iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_9;
            }
            if (vap->iv_vht_rx_mcsmap) {
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS4_MASK);
            }
#endif
    }
    if(vap->iv_configured_vht_mcsmap) {
        /* rx and tx vht mcs will be same for iv_configured_vht_mcsmap option */
        /* Assign either rx or tx mcs map back to this variable so that iwpriv get operation prints exact value */
        vap->iv_configured_vht_mcsmap = vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map;
    }
    vap->iv_set_vht_mcsmap = true;
}


/*
 * This function updates the VHTCAP based on the
 * MU-CAP WAR variable status
 */
static inline u_int32_t mu_cap_war_probe_response_change(u_int32_t vhtcap_info,
                                             u_int8_t subtype,
                                             struct ieee80211vap  *vap,
                                             struct ieee80211_node *ni,
                                             struct ieee80211com *ic,
                                             u_int8_t *sta_mac_addr,
                                             MU_CAP_WAR *war)
{
    struct DEDICATED_CLIENT_MAC *dedicated_mac = NULL;
    int hash;
    u_int32_t vhtcap_info_modified = vhtcap_info;
    if (!war->mu_cap_war ||
        !war->modify_probe_resp_for_dedicated ||
        !ni->dedicated_client ||
        (subtype !=  IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
        (!(vhtcap_info&IEEE80211_VHTCAP_MU_BFORMER))) {

        /*
         * No need to change the existing VHT-CAP
         * or do any further processing
         */
        return vhtcap_info;
    }

    /*
     * Hacking the VHT-CAP so that
     * the dedicated client joins as SU-2x2
     */
    vhtcap_info_modified &= ~IEEE80211_VHTCAP_MU_BFORMER;

    if (sta_mac_addr == NULL) {
        ieee80211_note(vap, IEEE80211_MSG_ANY,
                      "ERROR!!! NULL STA_MAC_ADDR Passed to %s\n",
                      __func__);
        return vhtcap_info;
    }

    hash = IEEE80211_NODE_HASH(sta_mac_addr);
    LIST_FOREACH(dedicated_mac, &war->dedicated_client_list[hash], list) {
        if (IEEE80211_ADDR_EQ(dedicated_mac->macaddr, sta_mac_addr)) {

            /*
             * Entry already present, no need to add again
             */
            return vhtcap_info_modified;
        }
    }


    /*
     * Have at the most, twice as many floating ProbeResponse-hacked clients
     * as the number of clients supported
     * The multiply-by-2 is an arbitrary ceiling limit. To remove
     * this limit, there should be timer logic to periodically flush
     * out old Probe-Response-hacked clients from the database.
     * At this point this does not seem to be a priority.
     */
    if (war->dedicated_client_number >= (MAX_PEER_NUM*2)) {
        ieee80211_note(vap, IEEE80211_MSG_ANY,
                "ERROR!! Too many floating PR clients, we might run out of %s",
                "memory if we keep adding these clients to DB\n");
        return vhtcap_info;
    }

    /*
     * Maintain the list of clients to which
     * we send this 'hacked' VHTCAP in probe response
     */
    dedicated_mac =
        OS_MALLOC(ic->ic_osdev, sizeof(*dedicated_mac), 0);
    if (dedicated_mac == NULL) {
        ieee80211_note(vap, IEEE80211_MSG_ANY, "ERROR!! Memory allocation failed in %s\n",
                __func__);
        return vhtcap_info;
    }
    OS_MEMSET(dedicated_mac, 0, sizeof(*dedicated_mac));
    OS_MEMCPY(dedicated_mac->macaddr, sta_mac_addr,
            sizeof(dedicated_mac->macaddr));
    war->dedicated_client_number++;
    LIST_INSERT_HEAD(&war->dedicated_client_list[hash], dedicated_mac, list);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
            "Adding %s to modified probe-resp list\n",
                    ether_sprintf(sta_mac_addr));
    return vhtcap_info_modified;
}


u_int8_t *
ieee80211_add_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype,
                     struct ieee80211_framing_extractx *extractx,
                     u_int8_t *sta_mac_addr)
{
    int vhtcaplen = sizeof(struct ieee80211_ie_vhtcap);
    struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)frm;
    struct ieee80211vap  *vap = ni->ni_vap;
    u_int32_t vhtcap_info;
    u_int32_t ni_vhtbfeestscap;
    u_int32_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int32_t tx_streams = ieee80211_get_txstreams(ic, vap);
    ieee80211_vht_rate_t ni_tx_vht_rates;
    struct supp_tx_mcs_extnss tx_mcs_extnss_cap;
    u_int16_t temp;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    vhtcap->elem_id   = IEEE80211_ELEMID_VHTCAP;
    vhtcap->elem_len  = sizeof(struct ieee80211_ie_vhtcap) - 2;

    /* Fill in the VHT capabilities info */
    vhtcap_info = ic->ic_vhtcap;

    /* Use firmware short GI capability if short GI is enabled on this vap.
     * Else clear short GI for both 80 and 160 MHz.
     */
    if (!vap->iv_sgi) {
        vhtcap_info &= ~(IEEE80211_VHTCAP_SHORTGI_80 | IEEE80211_VHTCAP_SHORTGI_160);
    }

    vhtcap_info &= ((vap->iv_ldpc & IEEE80211_HTCAP_C_LDPC_RX) ?  ic->ic_vhtcap  : ~IEEE80211_VHTCAP_RX_LDPC);

    if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
        (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Check negotiated Rx NSS */
        ieee80211_get_vht_rates(ni->ni_rx_vhtrates, &ni_tx_vht_rates);
        rx_streams = MIN(rx_streams, ni_tx_vht_rates.num_streams);
    }

    /* Adjust the TX and RX STBC fields based on the chainmask and config status */
    vhtcap_info &= (((vap->iv_tx_stbc) && (tx_streams > 1)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_TX_STBC);
    vhtcap_info &= (((vap->iv_rx_stbc) && (rx_streams > 0)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_RX_STBC);

    /* Support WFA R1 test case -- beamformer & nss =1*/
    if(tx_streams > 1)
    {
        vhtcap_info &= ((vap->iv_vhtsubfer) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_SU_BFORMER);
    }else{
        vhtcap_info &= (((vap->iv_vhtsubfer) && (vap->iv_vhtsubfee) && (vap->iv_vhtmubfer == 0)
                         &&(vap->iv_vhtmubfee == 0) && (vap->iv_nss == 1)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_SU_BFORMER);
    }
    vhtcap_info &= ((vap->iv_vhtsubfee) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_SU_BFORMEE);



    /* if SU Beamformer/Beamformee is not set then MU Beamformer/Beamformee need to be disabled */
    vhtcap_info &= (((vap->iv_vhtsubfer) && (vap->iv_vhtmubfer) && (tx_streams > 1)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_MU_BFORMER);
    vhtcap_info = mu_cap_war_probe_response_change(vhtcap_info, subtype, 
                                                   vap, ni, ic, sta_mac_addr,
                                                   &vap->iv_mu_cap_war);
    ni->dedicated_client = 0;
    vhtcap_info &= (((vap->iv_vhtsubfee) && (vap->iv_vhtmubfee) && (rx_streams < 3)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_MU_BFORMEE);
    vhtcap_info &= ~(IEEE80211_VHTCAP_STS_CAP_M << IEEE80211_VHTCAP_STS_CAP_S);
    if ((extractx != NULL) &&
        (extractx->fectx_nstscapwar_reqd == true) &&
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Using client's NSTS CAP value for assoc response */
        ni_vhtbfeestscap = ((ni->ni_vhtcap >> IEEE80211_VHTCAP_STS_CAP_S) &
                                IEEE80211_VHTCAP_STS_CAP_M );
        vhtcap_info |= (((vap->iv_vhtbfeestscap <= ni_vhtbfeestscap) ? vap->iv_vhtbfeestscap:ni_vhtbfeestscap) << IEEE80211_VHTCAP_STS_CAP_S);
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ASSOC, "%s:nsts war:: vap_stscap %#x,ni_stscap %#x,vhtcap:%#x\n",__func__, vap->iv_vhtbfeestscap,ni_vhtbfeestscap,vhtcap_info);
    }else {
        vhtcap_info |= vap->iv_vhtbfeestscap << IEEE80211_VHTCAP_STS_CAP_S;
    }
    vhtcap_info &= ~IEEE80211_VHTCAP_SOUND_DIM;
    if((vap->iv_vhtsubfer) && (tx_streams > 1)) {
        vhtcap_info |= ((vap->iv_vhtbfsoundingdim < (tx_streams - 1)) ? vap->iv_vhtbfsoundingdim : (tx_streams - 1)) << IEEE80211_VHTCAP_SOUND_DIM_S;
    }

    /* Clear supported chanel width first */
    vhtcap_info &= ~(IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
                     IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160);

    /* Set supported chanel width as per current operating mode.
     * We don't need to check for HW/FW announced channel width
     * capability as this is already verified in service_ready_event.
     */
    if (!vap->iv_ext_nss_support) {
        if (vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT80_80) {
            vhtcap_info |= IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160;
        } else if (vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT160) {
            vhtcap_info |= IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160;
        }
    } else if (!ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        /* If AP supports EXT NSS Signaling, set vhtcap ie to
         * IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE,
         * IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5,
         * IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1 or
         * IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE
         * as they are the only valid combination for our chipsets.
         */
        if (vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT80_80) {
            if (nssmap.flag & IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW) {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1;
            } else {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5;
            }
        } else if (vap->iv_cur_mode == IEEE80211_MODE_11AC_VHT160) {
            if (nssmap.flag & IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW) {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE;
            } else {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE;
            }
        }
    }

    /* We currently honor a 160 MHz association WAR request from callers only
     * for IEEE80211_FC0_SUBTYPE_PROBE_RESP and IEEE80211_FC0_SUBTYPE_ASSOC_RESP.
     */
    if ((extractx != NULL) &&
        (extractx->fectx_assocwar160_reqd == true) &&
        ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP))) {
       /* Remove all indications of 160 MHz capability, to enable the STA to
        * associate.
        */
       vhtcap_info &= ~(IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
                        IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
                        IEEE80211_VHTCAP_SHORTGI_160);
    }

    vhtcap->vht_cap_info = htole32(vhtcap_info);

    /* Fill in the VHT MCS info */
    ieee80211_set_vht_rates(ic,vap);
    vhtcap->rx_high_data_rate = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.data_rate);
    tx_mcs_extnss_cap.tx_high_data_rate = (vap->iv_vhtcap_max_mcs.tx_mcs_set.data_rate);
    vhtcap->tx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map);
    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) {
        if(!((ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160)||
             (ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160))) {
            /* if not 160, advertise rx mcs map as per vap max */
            vhtcap->rx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map);
        } else {
            /* if 160 , advertise rx mcs map as of ni ( negotiated ap) rx mcs map*/
            vhtcap->rx_mcs_map = htole16(ni->ni_rx_vhtrates);
        }
    } else if((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        vhtcap->rx_mcs_map = htole16(ni->ni_rx_vhtrates);
    } else {
        vhtcap->rx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map);
    }

    tx_mcs_extnss_cap.ext_nss_capable = !!(vap->iv_ext_nss_capable);
    tx_mcs_extnss_cap.reserved = 0;
    temp = htole16(*(u_int16_t *)&tx_mcs_extnss_cap);
    OS_MEMCPY(&vhtcap->tx_mcs_extnss_cap, &temp, sizeof(u_int16_t));
    return frm + vhtcaplen;
}

u_int8_t *
ieee80211_add_interop_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype)
{
    int vht_interopcaplen = sizeof(struct ieee80211_ie_interop_vhtcap);
    struct ieee80211_ie_interop_vhtcap *vht_interopcap = (struct ieee80211_ie_interop_vhtcap *)frm;
    static const u_int8_t oui[4] = { VHT_INTEROP_OUI_BYTES, VHT_INTEROP_TYPE};

    vht_interopcap->elem_id   = IEEE80211_ELEMID_VENDOR;
    if ((subtype == IEEE80211_FC0_SUBTYPE_BEACON)||(subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) ||
                                                   (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)) {
        vht_interopcap->elem_len  = sizeof(struct ieee80211_ie_interop_vhtcap) - 2;
        vht_interopcaplen =  sizeof(struct ieee80211_ie_interop_vhtcap);
    }
    else {
        vht_interopcap->elem_len  = sizeof(struct ieee80211_ie_interop_vhtcap) - 9; /* Eliminating Vht op IE */
        vht_interopcaplen =  sizeof(struct ieee80211_ie_interop_vhtcap) - 7;
    }

    /* Fill in the VHT capabilities info */
    memcpy(&vht_interopcap->vht_interop_oui,oui,sizeof(oui));
    vht_interopcap->sub_type = ni->ni_vhtintop_subtype;
    ieee80211_add_vhtcap(frm + 7 , ni, ic, subtype, NULL, NULL); /* Vht IE location Inside Vendor specific VHT IE*/


    if ((subtype == IEEE80211_FC0_SUBTYPE_BEACON)||(subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) ||
                                                   (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)) {
       ieee80211_add_vhtop(frm + 21 , ni, ic, subtype, NULL); /* Adding Vht Op IE after Vht cap IE  inside Vendor VHT IE*/
    }
    return frm + vht_interopcaplen;
}


u_int8_t *
ieee80211_add_vhtop(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype,
                    struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_ie_vhtop *vhtop = (struct ieee80211_ie_vhtop *)frm;
    int vhtoplen = sizeof(struct ieee80211_ie_vhtop);
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t chwidth = 0, negotiate_bw = 0;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    vhtop->elem_id   = IEEE80211_ELEMID_VHTOP;
    vhtop->elem_len  = sizeof(struct ieee80211_ie_vhtop) - 2;

    ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask);

    if((ni->ni_160bw_requested == 1) && (IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) ||
                IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan)) &&
            (ni->ni_chwidth == IEEE80211_VHTOP_CHWIDTH_80) &&
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Set negotiated BW */
        chwidth = ni->ni_chwidth;
        negotiate_bw = 1;
    } else {
       if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
           chwidth = vap->iv_chwidth;
       } else {
           chwidth = ic_cw_width;
       }
    }

    /* Fill in the VHT Operation info */
    if (chwidth == IEEE80211_CWM_WIDTH160) {
        if (vap->iv_rev_sig_160w) {
            if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80;
            else
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_REVSIG_160;
        } else {
            if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_80_80;
            else
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_160;
        }
    }
    else if (chwidth == IEEE80211_CWM_WIDTH80)
        vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_80;
    else
        vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_2040;

    if (negotiate_bw == 1) {

            vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_freq_seg1;
            /* Note: This is applicable only for 80+80Mhz mode */
            vhtop->vht_op_ch_freq_seg2 = 0;
    }
    else {
        if (chwidth == IEEE80211_CWM_WIDTH160) {

            if (vap->iv_rev_sig_160w) {
                /* Our internal channel structure is in sync with
                 * revised 160 MHz signalling. So use seg1 and
                 * seg2 directly for 80_80 and 160.
                 */
                if (vap->iv_ext_nss_support && (!(nssmap.flag & IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW))) {
                    /* If EXT NSS is enabled in driver, vht_op_ch_freq_seq2
                     * has to be populated in htinfo IE, for the combination of NSS values
                     * for 80, 160 and 80+80 MHz which our hardware supports.
                     * Exception to this is when AP is forced to come up with same NSS value for
                     * both 80+80MHz and 160MHz */
                    vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_freq_seg1;
                    vhtop->vht_op_ch_freq_seg2 = 0;
                } else {
                    vhtop->vht_op_ch_freq_seg1 = 
                           vap->iv_bsschan->ic_vhtop_ch_freq_seg1;

                    vhtop->vht_op_ch_freq_seg2 =
                        vap->iv_bsschan->ic_vhtop_ch_freq_seg2;
                }
            } else {
                /* Use legacy 160 MHz signaling */
                if(IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan)) {
                    /* ic->ic_curchan->ic_vhtop_ch_freq_seg2 is centre
                     * frequency for whole 160 MHz.
                     */
                    vhtop->vht_op_ch_freq_seg1 =
                        vap->iv_bsschan->ic_vhtop_ch_freq_seg2;
                    vhtop->vht_op_ch_freq_seg2 = 0;
                } else {
                    /* 80 + 80 MHz */
                    vhtop->vht_op_ch_freq_seg1 =
                        vap->iv_bsschan->ic_vhtop_ch_freq_seg1;

                    vhtop->vht_op_ch_freq_seg2 =
                        vap->iv_bsschan->ic_vhtop_ch_freq_seg2;
                }
            }
       } else { /* 80MHZ or less */
            vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_freq_seg1;
            vhtop->vht_op_ch_freq_seg2 = 0;
        }
    }


    /* We currently honor a 160 MHz association WAR request from callers only for
     * IEEE80211_FC0_SUBTYPE_PROBE_RESP and IEEE80211_FC0_SUBTYPE_ASSOC_RESP, and
     * check if our current channel is for 160/80+80 MHz.
     */
    if ((!vap->iv_rev_sig_160w) && (extractx != NULL) &&
        (extractx->fectx_assocwar160_reqd == true) &&
        ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) &&
        (IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) ||
            IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))) {
       /* Remove all indications of 160 MHz capability, to enable the STA to
        * associate.
        *
        * Besides, we set vht_op_chwidth to IEEE80211_VHTOP_CHWIDTH_80 without
        * checking if preceeding code had set it to lower value negotiated with
        * STA. This is for logical conformance with older VHT AP behaviour
        * wherein width advertised would remain constant across probe response
        * and assocation response.
        */

        /* Downgrade to 80 MHz */
        vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_80;

        vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_freq_seg1;
        vhtop->vht_op_ch_freq_seg2 = 0;
    }

    /* Fill in the VHT Basic MCS set */
    vhtop->vhtop_basic_mcs_set =  htole16(ic->ic_vhtop_basic_mcs);

    return frm + vhtoplen;
}

u_int8_t *
ieee80211_add_vht_txpwr_envlp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t is_subelement)
{
    struct ieee80211_ie_vht_txpwr_env *txpwr = (struct ieee80211_ie_vht_txpwr_env *)frm;
    int txpwr_len;
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t max_pwr;
    struct ieee80211_channel *channel = NULL;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if(scn->target_type == TARGET_TYPE_QCA9984  || scn->target_type == TARGET_TYPE_QCA9888) {
        txpwr_len = sizeof(struct ieee80211_ie_vht_txpwr_env) -
            (IEEE80211_VHT_TXPWR_MAX_POWER_COUNT - IEEE80211_VHT_TXPWR_NUM_POWER_SUPPORTED);
    }
    else {
        txpwr_len = sizeof(struct ieee80211_ie_vht_txpwr_env) -
            (IEEE80211_VHT_TXPWR_MAX_POWER_COUNT - (IEEE80211_VHT_TXPWR_NUM_POWER_SUPPORTED - 1));
    }

    txpwr->elem_id   = IEEE80211_ELEMID_VHT_TX_PWR_ENVLP;
    txpwr->elem_len  = txpwr_len - 2;

    if(!is_subelement) {
       channel = vap->iv_bsschan;
    }
    else {
       if(is_subelement == IEEE80211_VHT_TXPWR_IS_VENDOR_SUB_ELEMENT)
           channel = ic->ic_tx_next_ch;
       else
           channel = ic->ic_chanchange_channel;
    }
    /*
     * Max Transmit Power count = 2( 20,40 and 80MHz) and
     * Max Transmit Power units = 0 (EIRP)
     */

    if(scn->target_type == TARGET_TYPE_QCA9984 || scn->target_type == TARGET_TYPE_QCA9888) {
        txpwr->txpwr_info = IEEE80211_VHT_TXPWR_NUM_POWER_SUPPORTED - 1;
    }
    else {
        txpwr->txpwr_info = (IEEE80211_VHT_TXPWR_NUM_POWER_SUPPORTED -1) - 1;
    }

    /* Tx Power is specified in 0.5dB steps  2's complement representation */
    max_pwr = channel->ic_maxregpower;
    txpwr->local_max_txpwr[0] = txpwr->local_max_txpwr[1] =
    txpwr->local_max_txpwr[2] = ~(max_pwr * 2) + 1;

    if(scn->target_type == TARGET_TYPE_QCA9984 || scn->target_type == TARGET_TYPE_QCA9888) {
        txpwr->local_max_txpwr[3] = ~(max_pwr * 2) + 1;
    }

    return frm + txpwr_len;
}


/**
* @brief    Adds wide band sub element within channel switch wrapper IE.
*           If this function is to be used for 'Wide Bandwidth Channel Switch
*           element', then modifications will be required in function.
*
* @param frm        frame in which this sub element should be added
* @param ni         pointer to associated node structure
* @param ic         pointer to iee80211com
* @param subtype    frame subtype (beacon, probe resp etc.)
*
* @return pointer to post channel switch sub element
*/
u_int8_t*
ieee80211_add_vht_wide_bw_switch(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, int is_vendor_ie)
{
    struct ieee80211_ie_wide_bw_switch *widebw = (struct ieee80211_ie_wide_bw_switch *)frm;
    int widebw_len = sizeof(struct ieee80211_ie_wide_bw_switch);
    u_int8_t    new_ch_width = 0;
    enum ieee80211_phymode new_phy_mode;
    u_int8_t                      next_chan;
    u_int16_t                     next_chwidth;
    struct ieee80211_channel      *next_channel;

    if(is_vendor_ie)
    {
        next_chan = ic->ic_tx_next_ch->ic_ieee;
        next_chwidth = ieee80211_get_chan_width(ic->ic_tx_next_ch);
        next_channel = ic->ic_tx_next_ch;
    }
    else
    {
        next_chan = ic->ic_chanchange_chan;
        next_chwidth = ic->ic_chanchange_chwidth;
        next_channel = ic->ic_chanchange_channel;
    }

    OS_MEMSET(widebw, 0, sizeof(struct ieee80211_ie_wide_bw_switch));

    widebw->elem_id   = IEEE80211_ELEMID_WIDE_BAND_CHAN_SWITCH;
    widebw->elem_len  = widebw_len - 2;

    /* New channel width */
    switch(next_chwidth)
    {
        case CHWIDTH_VHT40:
            new_ch_width = IEEE80211_VHTOP_CHWIDTH_2040;
            break;
        case CHWIDTH_VHT80:
            new_ch_width = IEEE80211_VHTOP_CHWIDTH_80;
            break;
        case CHWIDTH_VHT160:
            if (IEEE80211_IS_CHAN_11AC_VHT160(next_channel)) {
                new_ch_width = IEEE80211_VHTOP_CHWIDTH_160;
            } else if (IEEE80211_IS_CHAN_11AC_VHT80_80(next_channel)) {
                new_ch_width = IEEE80211_VHTOP_CHWIDTH_80_80;
            } else {
                qdf_print("%s: Error: chanwidth 160 requested for a channel"
                        " which is neither VHT160 nor VHT80_80, flags: 0x%x\n",
                        __func__, next_channel->ic_flags);
                qdf_assert_always(0);
            }
            break;
        default:
            QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Invalid destination channel width %d specified\n",
                    __func__, next_chwidth);
            qdf_assert_always(0);
            break;
    }

     /* Channel Center frequency 1 */
    if(new_ch_width != IEEE80211_VHTOP_CHWIDTH_2040) {

       widebw->new_ch_freq_seg1 = next_channel->ic_vhtop_ch_freq_seg1;
       widebw->new_ch_freq_seg2 = 0;
       if(new_ch_width == IEEE80211_VHTOP_CHWIDTH_80_80) {
           /* Channel Center frequency 2 */
           widebw->new_ch_freq_seg2 = next_channel->ic_vhtop_ch_freq_seg2;

       } else if(new_ch_width == IEEE80211_VHTOP_CHWIDTH_160) {
           /* Wide band IE definition in standard hasn't yet been changed
            * to align with new definition of VHT Op. Announce whole 160 MHz
            * channel centre frequency in seg1 and 0 in seg2.
            */
           widebw->new_ch_freq_seg1 = next_channel->ic_vhtop_ch_freq_seg2;
       }
    } else {
        new_phy_mode = ieee80211_chan2mode(ic->ic_chanchange_channel);

        if(new_phy_mode == IEEE80211_MODE_11AC_VHT40PLUS) {
            widebw->new_ch_freq_seg1 = next_channel->ic_ieee + 2;
        } else if(new_phy_mode == IEEE80211_MODE_11AC_VHT40MINUS) {
            widebw->new_ch_freq_seg1 = next_channel->ic_ieee - 2;
        }
    }
    widebw->new_ch_width = new_ch_width;

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_DOTH,
         "%s: new_ch_width: %d, freq_seg1: %d, freq_seg2 %d\n", __func__,
         new_ch_width, widebw->new_ch_freq_seg1, widebw->new_ch_freq_seg2);

    return frm + widebw_len;
}

u_int8_t *
ieee80211_add_chan_switch_wrp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t extchswitch)
{
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t *efrm;
    u_int8_t ie_len;
    /* preserving efrm pointer, if no sub element is present,
        Skip adding this element */
    efrm = frm;
     /* reserving 2 bytes for the element id and element len*/
    frm += 2;

    /*country element is added if it is extended channel switch*/
    if (extchswitch) {
        frm = ieee80211_add_country(frm, vap);
    }
    /*If channel width not 20 then add Wideband and txpwr evlp element*/
    if(ic->ic_chanchange_chwidth != CHWIDTH_VHT20) {
        if (ic->ic_wb_subelem) {
            frm = ieee80211_add_vht_wide_bw_switch(frm, ni, ic, subtype, 0);
        }

        frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic, subtype,
                                    IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
    }
    /* If frame is filled with sub elements then add element id and len*/
    if((frm-2) != efrm)
    {
       ie_len = frm - efrm - 2;
       *efrm++ = IEEE80211_ELEMID_CHAN_SWITCH_WRAP;
       *efrm = ie_len;
       /* updating efrm with actual index*/
       efrm = frm;
    }
    return efrm;
}

#if ATH_BAND_STEERING
/**
 * @brief  Process power capability IE
 *
 * @param [in] ni  the STA that sent the IE
 * @param [in] ie  the IE to be processed
 */
void ieee80211_process_pwrcap_ie(struct ieee80211_node *ni, u_int8_t *ie)
{
    u_int8_t len;

    if (!ni || !ie) {
        return;
    }

    len = ie[1];
    if (len != 2) {
        IEEE80211_DISCARD_IE(ni->ni_vap,
            IEEE80211_MSG_ELEMID,
            "Power Cap IE", "invalid len %u", len);
        return;
    }

    ni->ni_max_txpower = ie[3];
}

/* extnss_160_validate_and_seg2_indicate() - Validate vhtcap if EXT NSS supported
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to validate vht capability combination of "supported chwidth" and "ext nss support"
 * along with indicating appropriate location to retrieve seg2 from(either htinfo or vhtop).
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : If seg2 is to be extracted from vhtop
 *          2 : If seg2 is to be extracted from htinfo
 *          0 : Failure
 */
u_int8_t extnss_160_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{

    if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE)) {
        return 0;
    }

    if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
        (vhtop->vht_op_ch_freq_seg2 != 0) &&
        (abs(vhtop->vht_op_ch_freq_seg2 - vhtop->vht_op_ch_freq_seg1) == 8)) {
            return 1;
        }
    } else if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
       if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
        (HTINFO_CCFS2_GET(htinfo) != 0) &&
        (abs(HTINFO_CCFS2_GET(htinfo) - vhtop->vht_op_ch_freq_seg1) == 8)) {
           return 2;
        }
    } else {
        return 0;
    }
      return 0;
}

/*  retrieve_seg2_for_extnss_160() - Retrieve seg2 based on vhtcap
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to retrieve seg2 from either vhtop or htinfo based on the
 * vhtcap advertised by the AP.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - vht_op_ch_freq_seg2
 */
u_int32_t  retrieve_seg2_for_extnss_160(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{
    u_int8_t val;

    val = extnss_160_validate_and_seg2_indicate(vhtcap, vhtop, htinfo);
    if (val == 1) {
       return vhtop->vht_op_ch_freq_seg2;
    } else if (val == 2) {
       return  HTINFO_CCFS2_GET(htinfo);
    } else {
       return 0;
    }
}

/* extnss_80p80_validate_and_seg2_indicate() - Validate vhtcap if EXT NSS supported
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to validate vht capability combination of "supported chwidth" and "ext nss support"
 * along with along with indicating appropriate location to retrieve seg2 from(either htinfo or vhtop)
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : If seg2 is to be extracted from vhtop
 *          2 : If seg2 is to be extracted from htinfo
 *          0 : Failure
 */
u_int8_t extnss_80p80_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{

    if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
        (vhtop->vht_op_ch_freq_seg2 != 0) &&
        (abs(vhtop->vht_op_ch_freq_seg2 - vhtop->vht_op_ch_freq_seg1) > 16)) {
            return 1;
        }
    } else if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
        if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
        (HTINFO_CCFS2_GET(htinfo) != 0) &&
        (abs(HTINFO_CCFS2_GET(htinfo) - vhtop->vht_op_ch_freq_seg1) > 16)) {
            return 2;
        }
    } else {
        return 0;
    }
    return 0;
}

/*  retrieve_seg2_for_extnss_80p80() - Retrieve seg2 based on vhtcap
 * @arg1 - struct ieee80211vap
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to retrieve seg2 from either vhtop or htinfo based on the
 * vhtcap advertised by the AP.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - Success : 0; Failure :1
 */
u_int32_t  retrieve_seg2_for_extnss_80p80(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{
    u_int8_t val;

    val = extnss_80p80_validate_and_seg2_indicate(vhtcap, vhtop, htinfo);
    if (val == 1) {
       return vhtop->vht_op_ch_freq_seg2;
    } else if (val == 2) {
       return  HTINFO_CCFS2_GET(htinfo);
    } else {
       return 0;
    }
}

/* validate_extnss_vhtcap() - Validate for valid combinations in vhtcap
 * @arg2 - vhtcap
 *
 * Function to validate vht capability combination of "supported chwidth"
 * and "ext nss support" advertised by STA.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : BW 160 supported
 *          0 : Failure
 */
bool validate_extnss_vhtcap(u_int32_t *vhtcap)
{
        if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) ==  IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE ) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
                   return true;
        }
    return false;
}
/* ext_nss_160_supported() - Validate 160MHz support for EXT NSS supported STA
 * @arg2 - vhtcap
 *
 * Function to validate vht capability combination of "supported chwidth"
 * and "ext nss support" advertised by STA for 160MHz.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : BW 160 supported
 *          0 : Failure
 */
bool ext_nss_160_supported(u_int32_t *vhtcap)
{
        if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) ==  IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE ) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
                   return true;
        }
    return false;
}

/* ext_nss_80p80_supported() - Validate 160MHz support for EXT NSS supported STA
 * @arg2 - vhtcap
 *
 * Function to validate vht capability combination of "supported chwidth"
 * and "ext nss support" advertised by STA fo 80+80 MHz.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : BW 80+80 supported
 *          0 : Failure
 */
bool ext_nss_80p80_supported(u_int32_t *vhtcap)
{
        if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5 ) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
                   return true;
        }
    return false;
}

/* peer_ext_nss_capable() - Validate peer EXT NSS capability
 * @arg1 - vhtcap
 *
 * Function to validate if peer is capable of EXT NSS Signaling
 *
 * Return - true : Peer is capable of EXT NSS
 *        - false : Peer not capable of EXT NSS
 */
bool peer_ext_nss_capable(struct ieee80211_ie_vhtcap * vhtcap)
{
    struct supp_tx_mcs_extnss tx_mcs_extnss_cap;
    OS_MEMCPY(&tx_mcs_extnss_cap, &vhtcap->tx_mcs_extnss_cap, sizeof(u_int16_t));
    *(u_int16_t *)&tx_mcs_extnss_cap = le16toh(*(u_int16_t*)&tx_mcs_extnss_cap);
    if (tx_mcs_extnss_cap.ext_nss_capable) {
        return true;
    }
    return false;
}
#endif
