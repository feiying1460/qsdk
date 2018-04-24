/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#include <osdep.h>

#include <ieee80211_var.h>

static	void *none_attach(struct ieee80211vap *, struct ieee80211_key *);
static	void none_detach(struct ieee80211_key *);
static	int none_setkey(struct ieee80211_key *);
static	int none_encap(struct ieee80211_key *, wbuf_t, u_int8_t);
static	int none_decap(struct ieee80211_key *, wbuf_t, int, struct ieee80211_rx_status *);
static	int none_enmic(struct ieee80211_key *, wbuf_t, int, bool);
static	int none_demic(struct ieee80211_key *, wbuf_t, int, int, struct ieee80211_rx_status *);

const struct ieee80211_cipher ieee80211_cipher_none = {
    "NONE",
    IEEE80211_CIPHER_NONE,
    0,
    0,
    0,
    none_attach,
    none_detach,
    none_setkey,
    none_encap,
    none_decap,
    none_enmic,
    none_demic,
};

static void *
none_attach(struct ieee80211vap *vap, struct ieee80211_key *k)
{
    return vap;		/* for diagnostics+stats */
}

static void
none_detach(struct ieee80211_key *k)
{
    return;
}

static int
none_setkey(struct ieee80211_key *k)
{
    (void) k;
    return 1;
}

static int
none_encap(struct ieee80211_key *k, wbuf_t wbuf, u_int8_t keyid)
{
    struct ieee80211vap *vap = k->wk_private;

    /*
     * The specified key is not setup; this can
     * happen, at least, when changing keys.
     */
    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_CRYPTO,
        ((struct ieee80211_frame *)wbuf_header(wbuf))->i_addr1,
        "key id %u is not set (encap)", keyid>>6);
    vap->iv_stats.is_tx_badcipher++;
    return 0;
}

static int
none_decap(struct ieee80211_key *k, wbuf_t wbuf, int hdrlen, struct ieee80211_rx_status *rs)
{
#ifdef IEEE80211_DEBUG
    struct ieee80211vap *vap = k->wk_private;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    const u_int8_t *ivp = (const u_int8_t *)&wh[1];

    /*
     * The specified key is not setup; this can
     * happen, at least, when changing keys.
     */
    /* XXX useful to know dst too */
    IEEE80211_NOTE_MAC(vap,
                       IEEE80211_MSG_CRYPTO, wh->i_addr2,
                       "cleartext used for key id %u (decap)",
                       ivp[IEEE80211_WEP_IVLEN] >> 6);
#endif
    return 0;
}

static int
none_enmic(struct ieee80211_key *k, wbuf_t wbuf, int force, bool encap)
{
    struct ieee80211vap *vap = k->wk_private;

    vap->iv_stats.is_tx_badcipher++;
    return 0;
}

static int
none_demic(struct ieee80211_key *k, wbuf_t wbuf, int hdrlen, int force, struct ieee80211_rx_status *rs)
{
    /* We should already update the stats in decap routine. */
    return 0;
}

void
ieee80211_crypto_register_none(struct ieee80211com *ic)
{
    ieee80211_crypto_register(ic, &ieee80211_cipher_none);
}

void
ieee80211_crypto_unregister_none(struct ieee80211com *ic)
{
    ieee80211_crypto_unregister(ic, &ieee80211_cipher_none);
}
