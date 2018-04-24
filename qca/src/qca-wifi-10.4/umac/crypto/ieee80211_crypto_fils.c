/*
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#include <ieee80211_crypto_fils_priv.h>
#include <ieee80211_crypto.h>
#include "aes.h"
#include "aes_siv.h"

int fils_parse_ie(wbuf_t wbuf, u_int8_t **cap_info,
                  u_int8_t **fils_sess, u_int8_t **ie_start);
static void * fils_aead_attach( struct ieee80211vap *vap,
                                struct ieee80211_key *k);
static void fils_aead_detach(struct ieee80211_key *k);
static int fils_aead_setkey(struct ieee80211_key *k);
static int fils_aead_encap(struct ieee80211_key *k, wbuf_t wbuf0,
                           u_int8_t keyid);
static int fils_aead_decap(struct ieee80211_key *k, wbuf_t wbuf,
                           int hdrlen, struct ieee80211_rx_status *rs);

static const struct ieee80211_cipher fils_aead = {
    "FILS AEAD",
    IEEE80211_CIPHER_FILS_AEAD,
    0,
    0,
    0,
    fils_aead_attach,
    fils_aead_detach,
    fils_aead_setkey,
    fils_aead_encap,
    fils_aead_decap,
    NULL,
    NULL,
};

/**
 * @brief Parse IE  and return required pointers to encrypt/decrypt routines
 *
 * @param [in] Packet buffer
 * @param [in] cap_info: Pointer to capability Information
 * @param [in] fils_sess: Pointer to the end of Fils session Element
 * @param [in] ie_start: Pointer to the start of Information element
 * @return 0 on success & -1 on error
 */
int
fils_parse_ie(wbuf_t wbuf, u_int8_t **cap_info, u_int8_t **fils_sess, u_int8_t **ie_start)
{
#define ASSOC_RESP_FIXED_FIELDS_LEN  6 /* cap info + status + assoc id */
#define ASSOC_REQ_FIXED_FIELDS_LEN   4 /* cap info + listen interval */
#define REASSOC_REQ_FIXED_FIELDS_LEN 10 /* cap info + listen interval + BSSID */
    struct ieee80211_frame *wh;
    u_int32_t pktlen_left = 0;
    bool fils_found = 0;
    int subtype = 0;
    u_int8_t *frm = NULL;
    u_int8_t elem_id;
    u_int32_t len;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    pktlen_left = wbuf_get_pktlen(wbuf);

    if(pktlen_left < sizeof(struct ieee80211_frame)) {
        qdf_print("%s Parse error.pktlen_left:%d Framehdr size:%d\n",
                __func__, pktlen_left, sizeof(struct ieee80211_frame));
        return -EINVAL;
    }

    frm = (u_int8_t *)&wh[1];
    pktlen_left -= sizeof(struct ieee80211_frame);

    /* pointer to the capability information field */
    *cap_info = (u_int8_t *)frm;

    if( subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP ||
        subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP ) {
        /* assoc resp frame - capability (2), status (2), associd (2) */
        if(pktlen_left < ASSOC_RESP_FIXED_FIELDS_LEN ) {
            qdf_print("%s Parse error.pktlen_left:%d Fixed Fields len:%d\n",
                    __func__, pktlen_left, ASSOC_RESP_FIXED_FIELDS_LEN);
            return -EINVAL;
        }

        frm += ASSOC_RESP_FIXED_FIELDS_LEN;
        pktlen_left -= ASSOC_RESP_FIXED_FIELDS_LEN;
    } else if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ) {
        /* assoc req frame - capability(2), listen interval (2) */
        if(pktlen_left < ASSOC_REQ_FIXED_FIELDS_LEN ) {
            qdf_print("%s Parse Error.pktlen_left:%d Fixed Fields len:%d\n",
                    __func__, pktlen_left, ASSOC_REQ_FIXED_FIELDS_LEN );
            return -EINVAL;
        }

        frm += ASSOC_REQ_FIXED_FIELDS_LEN;
        pktlen_left -= ASSOC_REQ_FIXED_FIELDS_LEN;
    } else if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
        /* assoc req frame - capability(2), listen interval(2), current AP address(6) */
        if(pktlen_left < REASSOC_REQ_FIXED_FIELDS_LEN ) {
            qdf_print("%sParse Error.pktlen_left:%d Fixed Fields len:%d\n",
                    __func__, pktlen_left, REASSOC_REQ_FIXED_FIELDS_LEN );
            return -EINVAL;
        }

        frm += REASSOC_REQ_FIXED_FIELDS_LEN;
        pktlen_left -= REASSOC_REQ_FIXED_FIELDS_LEN;
    }

    *ie_start = frm;
    /* 'frm' now pointing to TLVs.
     * Parse through All IE's till FILS Session Element
     */
    while ( (pktlen_left >= 2 ) && (frm != NULL) ) {
        /* element ID & len*/
        elem_id = *frm++;
        len = *frm++;
        pktlen_left -=2;

        /* for extension element, check the sub element ID */
        if (elem_id == IEEE80211_ELEMID_EXTENSION) {
            if ((len + 1) > pktlen_left) {
                qdf_print("%s Parse Error.pktlen_left:%did:%dlen:%dextid:%d\n",
                    __func__, pktlen_left, elem_id, len, *frm);
                return -EINVAL;
            }

            if (*frm == IEEE80211_ELEMID_EXT_FILS_SESSION) {
                fils_found = 1;
                break;
            }
            frm++;
            pktlen_left--;
        }

        if (len > pktlen_left) {
            qdf_print("%s Parse Error.pktlen_left:%did:%dlen:%dextid:%d\n",
                      __func__, pktlen_left, elem_id, len, *frm );
            return -EINVAL;
        }

        /* switch to the next IE */
        frm += len;
        pktlen_left -= len;
    }

    if(!fils_found)
    {
        qdf_print("%s FILS session element not found.Parse failed.\n",__func__);
        return -EINVAL;
    }

    /* Points to end of FILS session element */
    *fils_sess = (frm + len);

    return 0;
}


/**
 * @brief Attach FILS crypto
 *
 * @param [in] vap, Key structure
 * @return Pointer on success & NULL on error
 */
static void *
fils_aead_attach(struct ieee80211vap *vap, struct ieee80211_key *k)
{
    struct fils_ctx *ctx;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_FILS,"%s %d called \n",__func__, __LINE__);
    ctx = (struct fils_ctx *)qdf_mem_malloc(sizeof(struct fils_ctx));
    if (ctx == NULL) {
        vap->iv_stats.is_crypto_nomem++;
        return NULL;
    }

    ctx->fc_vap = vap;
    ctx->fc_ic = vap->iv_ic;
    return ctx;
}

/**
 * @brief Detach FILS crypto
 *
 * @param [in] Key structure
 * @return None
 */
static void
fils_aead_detach(struct ieee80211_key *k)
{
    struct fils_ctx *ctx = k->wk_private;
    if(ctx)
        OS_FREE(ctx);
}

/**
 * @brief setkey routine
 *
 * @param [in] Key structure
 * @return 1
 */
static int
fils_aead_setkey(struct ieee80211_key *k)
{
    return 1;
}

/**
 * @brief Encrypt FILS Association Response Packet
 *
 * @param [in] Key structure, wbuf, keyid
 * @return 1 on Success, 0 on Error
 */
static int
fils_aead_encap(struct ieee80211_key *k, wbuf_t wbuf, u_int8_t keyid)
{
    const u8 *address[5 + 1];
    size_t length[5 + 1];
    u_int8_t *cap_info = NULL , *fils_session = NULL, *ie_start = NULL;
    u_int32_t crypt_len = 0;
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    u8 *buf = NULL;
    u_int32_t bufsize = 0;

    if(ni == NULL) {
        qdf_print("%s %d Node could not be found Node\n",__func__, __LINE__);
        return 0;
    }

    if(!k->wk_filsaad.kek_len) {
        qdf_print("%s Key len is zero. Returning error \n", __func__);
        return 0;
    }

    if( fils_parse_ie(wbuf, &cap_info, &fils_session, &ie_start) < 0 )
    {
        qdf_print("%s FILS Parsing failed \n", __func__);
        return 0;
    }

    /* The AP's BSSID */
    address[0] = ni->ni_bssid;
    length[0] = ETH_ALEN;
    /* The STA's MAC address */
    address[1] = ni->ni_macaddr;
    length[1] = ETH_ALEN;
    /* The AP's nonce */
    address[2] = k->wk_filsaad.ANonce;
    length[2] = IEEE80211_FILS_NONCE_LEN;
    /* The STA's nonce */
    address[3] = k->wk_filsaad.SNonce;
    length[3] = IEEE80211_FILS_NONCE_LEN;
    address[4] = cap_info;
    length[4] = fils_session - cap_info;

    crypt_len = (u_int8_t *)wbuf_header(wbuf) + wbuf_get_pktlen(wbuf) - fils_session;

    bufsize = ((u_int8_t *)wbuf_header(wbuf) + wbuf_get_pktlen(wbuf) - ie_start) + AES_BLOCK_SIZE;
    buf = qdf_mem_malloc(bufsize);
    if (buf == NULL) {
        qdf_print("%s temp buf allocation failed \n",__func__);
        return 0;
    }
    qdf_mem_copy(buf, ie_start, bufsize);

    if (aes_siv_encrypt(k->wk_filsaad.kek,  k->wk_filsaad.kek_len,
                fils_session, crypt_len, 5, address, length, buf + (fils_session - ie_start)) <0) {
        qdf_print("%s aes siv_encryption failed \n",__func__);
        kfree(buf);
        return 0;
    }

    skb_put(wbuf, AES_BLOCK_SIZE);
    qdf_mem_copy(ie_start, buf, bufsize);
    kfree(buf);
    return 1;
}

/**
 * @brief Decrypt FILS Association Request Packet
 *
 * @param [in] Key structure, wbuf, hdrlen, rx_status
 * @return 1 on Success, 0 on Error
 */
static int
fils_aead_decap(struct ieee80211_key *k, wbuf_t wbuf, int hdrlen,
                struct ieee80211_rx_status *rs)
{
    const u8 *address[5];
    size_t length[5];
    u_int8_t *cap_info = NULL , *fils_session = NULL, *ie_start = NULL;
    u_int32_t crypt_len = 0;
    struct ieee80211_node *ni = wbuf_get_node(wbuf);
    u8 *buf = NULL;
    u_int32_t bufsize = 0;

    if(ni == NULL) {
        qdf_print("%s %d Node could not be found \n",__func__, __LINE__);
        return 0;
    }

    if(!k->wk_filsaad.kek_len) {
        qdf_print("%s Key len is zero. Returning error \n", __func__);
        return 0;
    }

    if(fils_parse_ie (wbuf, &cap_info, &fils_session, &ie_start) < 0){
        qdf_print("%s %d ie parse failed \n",__func__, __LINE__);
        return 0;
    }

    /* The STA's MAC address */
    address[0] = ni->ni_macaddr;
    length[0] = ETH_ALEN;
    /* The AP's BSSID */
    address[1] = ni->ni_bssid;
    length[1] = ETH_ALEN;
    /* The STA's nonce */
    address[2] = k->wk_filsaad.SNonce;
    length[2] = IEEE80211_FILS_NONCE_LEN;
    /* The AP's nonce */
    address[3] = k->wk_filsaad.ANonce;
    length[3] = IEEE80211_FILS_NONCE_LEN;

    address[4] = cap_info;
    length[4] = fils_session - cap_info;


    crypt_len = ((u_int8_t *)wbuf_header(wbuf) + wbuf_get_pktlen(wbuf)) - fils_session;
    if (crypt_len < AES_BLOCK_SIZE) {
        qdf_print("Not enough room for AES-SIV data after FILS Session element in \
                (Re)Association Request frame from %pM", ni->ni_macaddr);
        return -EINVAL;
    }

    //Allocate temp buf & copy contents
    bufsize = (u_int8_t *)wbuf_header(wbuf) + wbuf_get_pktlen(wbuf) - ie_start;
    buf = qdf_mem_malloc(bufsize);
    if (buf == NULL) {
        qdf_print("%s temp buf allocation failed \n",__func__);
        return 0;
    }
    qdf_mem_copy(buf, ie_start, bufsize);

    if (aes_siv_decrypt(k->wk_filsaad.kek, k->wk_filsaad.kek_len,
                        fils_session, crypt_len, 5, address, length,
                        buf + (fils_session - ie_start)) < 0) {
        qdf_print("%s AES decryption of assoc req frame from %s failed \n",
                  __func__, ether_sprintf(ni->ni_macaddr));
        kfree(buf);
        return 0;
    }
    qdf_mem_copy(ie_start, buf, bufsize);
    qdf_nbuf_trim_tail(wbuf, AES_BLOCK_SIZE);
    kfree(buf);
    return 1;
}

/**
 * @brief Register FILS crypto module
 *
 * @param [in] ic
 * @return none
 */
void
ieee80211_crypto_register_fils(struct ieee80211com *ic)
{
    ieee80211_crypto_register(ic, &fils_aead);
    return;
}

/**
 * @brief Unregister FILS crypto module
 *
 * @param [in] ic
 * @return none
 */
void
ieee80211_crypto_unregister_fils(struct ieee80211com *ic)
{
    ieee80211_crypto_unregister(ic, &fils_aead);
    return;
}
