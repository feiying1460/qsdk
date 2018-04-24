/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 MBO  module
*/

#include "ieee80211_mbo_priv.h"
#include "ieee80211_regdmn.h"

#if ATH_SUPPORT_MBO

/**
 * @brief Verify that the mbo handle is valid
 *
 * @param [in] VAP  the handle to the
 *
 * @return true if handle is valid; otherwise false
 */

static INLINE bool ieee80211_mbo_is_valid(const struct ieee80211vap *vap)
{
    return vap && vap->mbo;
}

/**
 * @brief Determine whether the VAP handle is valid,
 *        has a valid mbo handle,
 *        is operating in a mode where MBO is relevant,
 *        and is not in the process of being deleted.
 *
 * @return true if the VAP is valid; otherwise false
 */

bool ieee80211_mbo_is_vap_valid(const struct ieee80211vap *vap)
{
    /* Unfortunately these functions being used do not take a const pointer
       even though they do not modify the VAP. Thus, we have to cast away
       the const-ness in order to call them.*/

    struct ieee80211vap *nonconst_vap = (struct ieee80211vap *) vap;

    return vap && wlan_vap_get_opmode(nonconst_vap) == IEEE80211_M_HOSTAP &&
           !ieee80211_vap_deleted_is_set(nonconst_vap);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

bool ieee80211_vap_mbo_check(struct ieee80211vap *vap)
{
    if((ieee80211_mbo_is_vap_valid(vap)
        && ieee80211_mbo_is_valid(vap))
        && ieee80211_vap_mbo_is_set(vap))
        return true;
    else
        return false;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */
bool ieee80211_vap_mbo_assoc_status(struct ieee80211vap *vap)
{
    if (vap->mbo->usr_assoc_disallow) 
        return true;
    else 
        return false;
}
void ieee80211_mbo_help(u_int32_t param)
{
    switch(param) {
        case MBO_ATTRIB_CAP_INDICATION:
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " 0th bit- reserved\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " 1st bit- Non-preferred channel report capability\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " 2nd bit- MBO Cellular capabilities\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " 3rd bit- Association disallowed capability\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " 4th bit- Cellular data link request capability\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " 5th-7th bits- reserved\n");
            }
            break;
        case MBO_ATTRIB_ASSOCIATION_DISALLOWED:
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 0- reserved\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 1- Unspecified reason\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 2- Max no. of associated STAs reached\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 3- Air interface overloaded\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 4- Authentication server overloaded\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 5- Insufficient RSSI\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " value 6-255- reserved\n");
            }
            break;
        case MBO_ATTRIB_TRANSITION_REASON:
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 0- unspecified\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 1- Excessive frame loss rate\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 2- Excessive delay for current traffic stream\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 3- Insufficient bandwidth for current traffic stream\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 4- Load balancing\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 5- Low RSSI\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 6- Received excessive number of retransmissions\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 7- High interference\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 8- Gray zone\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 9- Transitioning to premium AP\n");
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Code 10-255- reserved\n");
            }
            break;
    }
    return;
}
/**
 * set simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : config paramter
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */

int wlan_set_mbo_param(wlan_if_t vap, u_int32_t param, u_int32_t val)
{
    int retv = EOK;
    ieee80211_mbo_t mbo = NULL;

    if(!ieee80211_mbo_is_vap_valid(vap))
        return EINVAL;

    if (!ieee80211_mbo_is_valid(vap))
        return EINVAL;

    mbo = vap->mbo;

    switch(param) {
    case IEEE80211_MBO:
        {
            if(val)
                ieee80211_vap_mbo_set(vap);
            else {
                ieee80211_vap_mbo_clear(vap);
            }
        }
        break;
    case IEEE80211_MBOCAP:
        {
            if (ieee80211_vap_mbo_is_set(vap) ) {
                if(val & MBO_CAP_AP_CELLULAR)
                    mbo->usr_mbocap_cellular_capable =  1;
                else
                    mbo->usr_mbocap_cellular_capable =  0;
            } else {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Need to enable MBO Before setting capability \n");
                retv = EINVAL;
            }
        }
        break;
    case IEEE80211_MBO_ASSOC_DISALLOW:
        {
#define MBO_MAX_ASSOC_DISALLOW 0x06
            if (!ieee80211_vap_mbo_is_set(vap)) {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "MBO not enabled \n");
                retv = EINVAL;
            } else if (val < MBO_MAX_ASSOC_DISALLOW) {
                mbo->usr_assoc_disallow = (u_int8_t)val;
                vap->iv_flags_ext2 |= IEEE80211_FEXT2_MBO;
            } else {
                QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "__Invalid argument __investigate__ \n");
                ieee80211_mbo_help(MBO_ATTRIB_ASSOCIATION_DISALLOWED);
                retv = EINVAL;
            }
        }
#undef MBO_MAX_ASSOC_DISALLOW
        break;
    case IEEE80211_MBO_CELLULAR_PREFERENCE:
        if ((val <= MBO_CELLULAR_PREFERENCE_NOT_USE) ||
            (val == MBO_CELLULAR_PREFERENCE_USE)) /* as per specification */
            mbo->usr_cell_pref = val;
        else
            retv = EINVAL;
        break;
    case IEEE80211_MBO_TRANSITION_REASON:
        if (val <= MBO_TRANSITION_REASON_PREMIUM_AP ) /* as per specification */
           mbo->usr_trans_reason = val;
        else
            retv = EINVAL;
        break;
    case IEEE80211_MBO_ASSOC_RETRY_DELAY:
        mbo->usr_assoc_retry = val;
        break;
    default:
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid configuration __investigate %s \n",__func__);
        retv = EINVAL;
    }
    return retv;
}


/**
 * get simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : paramter.
 * @return value of the parameter.
 */

u_int32_t wlan_get_mbo_param(wlan_if_t vap, u_int32_t param)
{
    u_int32_t retv = 0;
    ieee80211_mbo_t mbo = NULL;

    if(!ieee80211_mbo_is_vap_valid(vap))
        return EINVAL;

    if (!ieee80211_mbo_is_valid(vap))
        return EINVAL;

    mbo = vap->mbo;

    switch(param) {
    case IEEE80211_MBO:
        {
            retv = ieee80211_vap_mbo_is_set(vap);
        }
        break;
    case IEEE80211_MBOCAP:
        {
            if (mbo->usr_mbocap_cellular_capable) {
                retv |= MBO_CAP_AP_CELLULAR;
            }
        }
        break;
    case IEEE80211_MBO_ASSOC_DISALLOW:
        {
            retv = mbo->usr_assoc_disallow;
        }
        break;
    case IEEE80211_MBO_CELLULAR_PREFERENCE:
        return mbo->usr_cell_pref;
    case IEEE80211_MBO_TRANSITION_REASON:
        return mbo->usr_trans_reason;
    case IEEE80211_MBO_ASSOC_RETRY_DELAY:
        return mbo->usr_assoc_retry;
    default:
        QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid configuration __investigate %s \n",__func__);
        return EINVAL;;
    }
    return retv;
}

/**
 * @brief Initialize the MBO infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */

int ieee80211_mbo_vattach(struct ieee80211vap *vap)
{

    ieee80211_mbo_t mbo = NULL;

    if(!ieee80211_mbo_is_vap_valid(vap))
        return EINVAL;

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:MBO Initialized \n",__func__);

    if(vap->mbo)
        return EINPROGRESS;

    mbo = (ieee80211_mbo_t)
        OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_mbo), 0);

    if(NULL == mbo) {
        return -ENOMEM;
    }

    OS_MEMZERO(mbo,sizeof(struct ieee80211_mbo));
    mbo->mbo_osdev = vap->iv_ic->ic_osdev;
    mbo->mbo_ic = vap->iv_ic;
    vap->mbo = mbo;

    return EOK;
}

/**
 * @brief deint the MBO infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */

int ieee80211_mbo_vdetach(struct ieee80211vap *vap)
{
    if (!ieee80211_mbo_is_valid(vap))
        return EINVAL;

    OS_FREE(vap->mbo);
    vap->mbo = NULL;

    QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: MBO terminated\n", __func__);
    return EOK;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

static inline u_int8_t ieee80211_mbo_fill_header(struct ieee80211_mbo_header *header,u_int8_t type,u_int8_t len)
{
    header->ie = type;
    header->len = len;
    return((u_int8_t)sizeof(struct ieee80211_mbo_header));
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_assoc_disallow_ie(struct ieee80211vap *vap,u_int8_t *frm,u_int8_t reason)
{
    struct ieee80211_assoc_disallow *assoc_ie  = (struct ieee80211_assoc_disallow *)frm;
    u_int8_t len = 0;
    len = ieee80211_mbo_fill_header(&(assoc_ie->header),MBO_ATTRIB_ASSOCIATION_DISALLOWED,0);

    assoc_ie->reason_code = reason;
    assoc_ie->header.len = sizeof(struct ieee80211_assoc_disallow) - len;
    frm = (u_int8_t *)(&assoc_ie->opt_ie[0]);
    return (u_int8_t)sizeof(struct ieee80211_assoc_disallow);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_assoc_retry_del_ie(struct ieee80211vap *vap,u_int8_t *frm,
                                          struct ieee80211_bstm_reqinfo *bstm_reqinfo)
{
    struct ieee80211_assoc_retry_delay *assoc_re_del_ie = (struct ieee80211_assoc_retry_delay *)frm;
    ieee80211_mbo_t mbo = NULL;
    u_int8_t len = 0;
    if ( vap ) {
        mbo = vap->mbo;
    }
    if (mbo == NULL){
        return len;
    }

    len = ieee80211_mbo_fill_header(&(assoc_re_del_ie->header),MBO_ATTRIB_ASSOC_RETRY_DELAY,0);
    assoc_re_del_ie->header.len = (sizeof(struct ieee80211_assoc_retry_delay) - len);
    assoc_re_del_ie->re_auth_delay = cpu_to_le16(mbo->usr_assoc_retry);
    return (u_int8_t)(sizeof(struct ieee80211_assoc_retry_delay));
}


/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_trans_reason_ie(struct ieee80211vap *vap,u_int8_t *frm,struct ieee80211_bstm_reqinfo *bstm_reqinfo)
{
    struct ieee80211_transit_reason_code *trans_reason_code_ie = (struct ieee80211_transit_reason_code *)frm;
    ieee80211_mbo_t mbo = NULL;
    u_int8_t len = 0,len_next_attr = 0;
    if ( vap ) {
        mbo = vap->mbo;
    }
    if (mbo == NULL){
        return len;
    }
    if (mbo->usr_trans_reason <= MBO_TRANSITION_REASON_PREMIUM_AP) {
        len = ieee80211_mbo_fill_header(&(trans_reason_code_ie->header),MBO_ATTRIB_TRANSITION_REASON ,0 );
        trans_reason_code_ie->header.len = (sizeof(struct ieee80211_transit_reason_code) - len);
        trans_reason_code_ie->reason_code = mbo->usr_trans_reason;
        frm = (u_int8_t *)&trans_reason_code_ie->opt_ie[0];
        len = sizeof(struct ieee80211_transit_reason_code);
    }
    if(!bstm_reqinfo->bssterm_inc)
        len_next_attr = ieee80211_setup_assoc_retry_del_ie(vap,frm,bstm_reqinfo);
    return (u_int8_t)(len_next_attr + len);

}

u_int8_t ieee80211_setup_trans_reason_ie_target(struct ieee80211vap *vap,u_int8_t *frm,struct ieee80211_bstm_reqinfo_target *bstm_reqinfo)
{
    struct ieee80211_transit_reason_code *trans_reason_code_ie = (struct ieee80211_transit_reason_code *)frm;
    u_int8_t len = 0;

    if (bstm_reqinfo->trans_reason <= IEEE80211_BSTM_REQ_REASON_INVALID) {
        len = ieee80211_mbo_fill_header(&(trans_reason_code_ie->header),MBO_ATTRIB_TRANSITION_REASON ,0 );
        trans_reason_code_ie->header.len = (sizeof(struct ieee80211_transit_reason_code) - len);
        trans_reason_code_ie->reason_code = bstm_reqinfo->trans_reason;
        frm = (u_int8_t *)&trans_reason_code_ie->reason_code;
        len = sizeof(struct ieee80211_transit_reason_code);
    }

    return len;
}


/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_cell_pref_ie(struct ieee80211vap *vap,u_int8_t *frm,struct ieee80211_bstm_reqinfo *bstm_reqinfo)
{
    struct ieee80211_cell_data_conn_pref *cell_pref_ie = (struct ieee80211_cell_data_conn_pref *)frm;
    ieee80211_mbo_t mbo = NULL;
    u_int8_t len = 0,len_next_attr = 0;
    /*
     * This ie should be sent only when cellular
     * capabilities are supported by the station.
     */

    if ( vap ) {
        mbo = vap->mbo;
    }
    if(mbo == NULL){
        return len;
    }

    len = ieee80211_mbo_fill_header(&(cell_pref_ie->header),MBO_ATTRIB_CELLULAR_PREFERENCE ,0 );
    frm = (u_int8_t *)&cell_pref_ie->opt_ie[0];
    len_next_attr = ieee80211_setup_trans_reason_ie(vap,frm,bstm_reqinfo);
    cell_pref_ie->header.len = (sizeof(struct ieee80211_cell_data_conn_pref)-len);
    cell_pref_ie->cell_pref  = mbo->usr_cell_pref;
    return (u_int8_t)(len_next_attr + sizeof(struct ieee80211_cell_data_conn_pref));

}
/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_mbo_cap_ie(u_int8_t *frm, u_int8_t cellular_aware)
{
    struct ieee80211_mbo_cap *cap = NULL;

    cap = (struct ieee80211_mbo_cap *)frm;
    OS_MEMSET(cap,0,sizeof(struct ieee80211_mbo_cap));
    ieee80211_mbo_fill_header(&(cap->header),
                                    MBO_ATTRIB_CAP_INDICATION,0);

    cap->cap_cellular = cellular_aware; /*Broadcasting this value in frame */
    cap->header.len =  sizeof(struct ieee80211_mbo_cap) -
                       sizeof(struct ieee80211_mbo_header);

    return sizeof(struct ieee80211_mbo_cap);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_mbo_attrs(struct ieee80211vap *vap,u_int8_t *frm)
{
    ieee80211_mbo_t mbo = NULL;
    u_int8_t *start = frm;

    /* mbo check already done  in caller */

    mbo = vap->mbo;

	frm += ieee80211_setup_mbo_cap_ie(frm, mbo->usr_mbocap_cellular_capable);
    if(mbo->usr_assoc_disallow) {
        frm += ieee80211_setup_assoc_disallow_ie(vap,frm,
                                                 mbo->usr_assoc_disallow);
    }
    return (frm - start);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t*
ieee80211_setup_mbo_ie_bstmreq(struct ieee80211vap *vap, u_int8_t *ie,
                               struct ieee80211_bstm_reqinfo *bstm_reqinfo,
                               u_int8_t *macaddr)
{

    u_int8_t len = 0,*frm = NULL;
    struct ieee80211_mbo_ie *mbo_ie = (struct ieee80211_mbo_ie *)ie;
    struct ieee80211_node *ni = NULL;

    if(!mbo_ie)
        return ie;

    ieee80211_mbo_fill_header(&(mbo_ie->header),IEEE80211_ELEMID_VENDOR,0);
    mbo_ie->oui[0] = 0x50;
    mbo_ie->oui[1] = 0x6f;
    mbo_ie->oui[2] = 0x9a;
    mbo_ie->oui_type = MBO_OUI_TYPE;

    frm = (u_int8_t *)&mbo_ie->opt_ie[0];

    /*
     * If cell cap not supported by STA don't send cell_pref_ie
     * To find out if cell cap is supported by this macaddr compare
     * macaddr to macaddr of all STAs connected to vap and when it
     * matches check cell cap description within mbo_attributes structure
     */
     ni = ieee80211_find_node(&vap->iv_ic->ic_sta, macaddr);

     if(!ni)
         return frm;

    if (ni->ni_mbo.cellular_cap == 0x01 )
        len = ieee80211_setup_cell_pref_ie(vap,frm,bstm_reqinfo);
    else
        len = ieee80211_setup_trans_reason_ie ( vap, frm, bstm_reqinfo );
    mbo_ie->header.len = len + (sizeof(struct ieee80211_mbo_ie) - sizeof(struct ieee80211_mbo_header));
    return (frm +len);
}

u_int8_t*
ieee80211_setup_mbo_ie_bstmreq_target(struct ieee80211vap *vap, u_int8_t *ie,
                               struct ieee80211_bstm_reqinfo_target *bstm_reqinfo,
                               u_int8_t *macaddr)
{

    u_int8_t len = 0,*frm = NULL;
    struct ieee80211_mbo_ie *mbo_ie = (struct ieee80211_mbo_ie *)ie;
    struct ieee80211_node *ni = NULL;

    if(!mbo_ie)
        return ie;

    ieee80211_mbo_fill_header(&(mbo_ie->header),IEEE80211_ELEMID_VENDOR,0);
    mbo_ie->oui[0] = MBO_OUI & 0xFF;
    mbo_ie->oui[1] = (MBO_OUI >> 8) & 0xFF;
    mbo_ie->oui[2] = (MBO_OUI >> 16) & 0xFF;
    mbo_ie->oui_type = MBO_OUI_TYPE;

    frm = (u_int8_t *)&mbo_ie->opt_ie[0];

    /*
     * If cell cap not supported by STA don't send cell_pref_ie
     * To find out if cell cap is supported by this macaddr compare
     * macaddr to macaddr of all STAs connected to vap and when it
     * matches check cell cap description within mbo_attributes structure
     */
     ni = ieee80211_find_node(&vap->iv_ic->ic_sta, macaddr);

     if(!ni)
         return frm;

    len = ieee80211_setup_trans_reason_ie_target( vap, frm, bstm_reqinfo );
    mbo_ie->header.len = len + (sizeof(struct ieee80211_mbo_ie) - sizeof(struct ieee80211_mbo_header));
    return (frm +len);
}


/**
 * @brief
 * @param [in]
 * @param [out]
 */

/*
 * Parse the MBO ie for non-preferred channel report attribute and
 * Cellular capabilities attirbute
 */

int
ieee80211_parse_mboie(u_int8_t *frm, struct ieee80211_node *ni)
{
    u_int len = frm[1];
    u_int non_preferred_channel_attribute_len;
    u_int num_chan = 0, non_pref_attribute = 0;
    u_int updated_len = 0;
    u_int slen;
    u_int  attribute_id;
    u_int  attribute_len;
    u_int oce_sta = 0;
#define MBO_IE_MIN_LEN 4
    if(len < MBO_IE_MIN_LEN){
        IEEE80211_DISCARD_IE(ni->ni_vap,
                IEEE80211_MSG_ELEMID | IEEE80211_MSG_MBO,
                "MBO IE", "too short, len %u", len);
        return -1;
    }

    /* no non-preferred channel report attribute and cellular
       capabilities attribute present*/

    if (len == MBO_IE_MIN_LEN){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " No attribute id present \n");
        goto end;
    }
    slen = len - 4;
    /*
     * Incrementing frm by 6 so that it will point to the mbo attribute id
     * 1 byte for element id
     * 1 byte for length
     * 3 bytes for MBO OUI
     * 1 byte for MBO OUI type
     */
    frm = frm + 6;

    while(slen > updated_len)
    {
        attribute_id = *frm++;
        switch(attribute_id){
            case MBO_ATTRIB_CELLULAR:
                {
                    attribute_len = *frm++;
                    ni->ni_mbo.cellular_cap = *frm++;
                }
                updated_len += attribute_len + 2;
                break;
            case MBO_ATTRIB_NON_PREFERRED_CHANNEL:
                {
                    non_preferred_channel_attribute_len = *frm++;
                    ni->ni_mbo.num_attr = 0;
                    if (non_preferred_channel_attribute_len == 0){
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No non preferred channel report \n");
                    }
                    else
                    {
                        if(non_pref_attribute < IEEE80211_MBO_NUM_NONPREF_CHAN_ATTR){
                           OS_MEMSET(ni->ni_mbo.channel[non_pref_attribute].channels,0,
                                     sizeof(ni->ni_mbo.channel[non_pref_attribute].channels));
                            ni->ni_mbo.channel[non_pref_attribute].operating_class = *frm++;
                            /* Find out # of channels by excluding op_class, preference, reason_code (3 bytes) */
                            ni->ni_mbo.channel[non_pref_attribute].num_channels =
                                non_preferred_channel_attribute_len - MBO_ATTRIB_NON_CHANNEL_LEN;
                            for(num_chan = 0; num_chan < ni->ni_mbo.channel[non_pref_attribute].num_channels; num_chan++)
                            {
                                ni->ni_mbo.channel[non_pref_attribute].channels[num_chan] = *frm++;
                            }
                            ni->ni_mbo.channel[non_pref_attribute].channels_preference = *frm++;
                            ni->ni_mbo.channel[non_pref_attribute].reason_preference   = *frm++;
                            non_pref_attribute++;
                            ni->ni_mbo.num_attr = non_pref_attribute;
                        }
                        else {
                            frm +=len;
                        }
                    }
                }
                updated_len += non_preferred_channel_attribute_len + 2;
                break;
            case MBO_ATTRIB_TRANSITION_REJECTION:
                attribute_len = *frm++;
                ni->ni_mbo.trans_reject_code = *frm++;
                updated_len += attribute_len + 2;
                break;
            case OCE_ATTRIB_CAP_INDICATION:
                attribute_len = *frm++;
                oce_sta = 1;
                ni->ni_mbo.oce_cap = *frm++;
                updated_len += attribute_len + 2;
                break;
            default:
                break;
        }
    }
    ni->ni_mbo.oce_sta = oce_sta;

end:
#undef MBO_IE_MIN_LEN
    return EOK;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

 /*
  * parse the WNM Notification request frame for mbo ie
  */
int ieee80211_parse_wnm_mbo_subelem(u_int8_t *frm, struct ieee80211_node *ni)
{
    u_int len = frm[1];
    u_int num_chan, non_pref_attribute = 0;
    u_int8_t attribute_id;
    u_int8_t *sfrm;
#define MBO_IE_MIN_LEN 4

    if(len < MBO_IE_MIN_LEN){
        IEEE80211_DISCARD_IE(ni->ni_vap,
                IEEE80211_MSG_ELEMID | IEEE80211_MSG_MBO,
                "MBO IE", "too short, len %u", len);
        return -1;
    }
    /*
     * Incrementing frm by 5 will make it point to the mbo attribute subelement
     * 1 byte for subelement id
     * 1 byte for length
     * 3 bytes for MBO OUI
     */
    sfrm = frm;
    while ((sfrm[0] == IEEE80211_ELEMID_VENDOR) &&
           (sfrm[2] == (MBO_OUI >>  0 & 0xFF)) &&
           (sfrm[3] == (MBO_OUI >>  8 & 0xFF)) &&
           (sfrm[4] == (MBO_OUI >> 16 & 0xFF))) {
        frm = sfrm + 5;
        attribute_id = *frm++;
        if (attribute_id == MBO_ATTRIB_NON_PREFERRED_CHANNEL) {
            // Non preferred channel report sub-element
            len = *(sfrm +1);
            if (len == 4) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No non preferred channels list is present \n");
                ni->ni_mbo.num_attr = 0;
            }
            else {
                if(non_pref_attribute < IEEE80211_MBO_NUM_NONPREF_CHAN_ATTR){
                    OS_MEMSET(ni->ni_mbo.channel[non_pref_attribute].channels,0,
                             sizeof(ni->ni_mbo.channel[non_pref_attribute].channels));
                    ni->ni_mbo.channel[non_pref_attribute].operating_class = *frm++;
                    /* Find out # of channels by excluding oui, oui_type, op_class, preference, reason_code (7 bytes) */
                    ni->ni_mbo.channel[non_pref_attribute].num_channels = (len < MBO_SUBELM_NON_CHANNEL_LEN) ?
                        0 : len - MBO_SUBELM_NON_CHANNEL_LEN;
                    for(num_chan = 0; num_chan < ni->ni_mbo.channel[non_pref_attribute].num_channels; num_chan++)
                    {
                        ni->ni_mbo.channel[non_pref_attribute].channels[num_chan] = *frm++;
                    }
                    ni->ni_mbo.channel[non_pref_attribute].channels_preference = *frm++;
                    ni->ni_mbo.channel[non_pref_attribute].reason_preference   = *frm++;
                    non_pref_attribute++;
                    ni->ni_mbo.num_attr = non_pref_attribute;
                }
            }
            sfrm += len + 2;
        } else if (attribute_id == MBO_ATTRIB_CELLULAR) {             // cellular capabilities sub-element
            len = *(sfrm +1);
            if(len < 5 ){
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "No cellular capabilities present \n");
            } else {
                ni->ni_mbo.cellular_cap = *(frm);
            }
            sfrm += len + 2;
        }
    }
#undef MBO_IE_MIN_LEN
    return EOK;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t*
ieee80211_setup_mbo_ie(int f_type, struct ieee80211vap *vap, u_int8_t *ie, struct ieee80211_node *ni)
{
    u_int8_t len = 0,*frm = NULL;
    struct ieee80211_mbo_ie *mbo_ie = (struct ieee80211_mbo_ie *)ie;

    OS_MEMSET(mbo_ie,0x00,sizeof(struct ieee80211_mbo_ie));
    ieee80211_mbo_fill_header(&(mbo_ie->header),IEEE80211_ELEMID_VENDOR,0);
    mbo_ie->oui[0] = 0x50;
    mbo_ie->oui[1] = 0x6f;
    mbo_ie->oui[2] = 0x9a;
    mbo_ie->oui_type = MBO_OUI_TYPE;

    frm = (uint8_t *)&mbo_ie->opt_ie[0];
	if (ieee80211_vap_mbo_check(vap)) {
		len += ieee80211_setup_mbo_attrs(vap, frm);
	}
	if (ieee80211_vap_oce_check(vap)) {
		len += ieee80211_setup_oce_attrs(f_type, vap, frm, ni);
	}

    mbo_ie->header.len = len + (sizeof(struct ieee80211_mbo_ie) - sizeof(struct ieee80211_mbo_header));
    return ( frm + len );

}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

/**
 * Using info parsed in supported operating classes ie
 * to derive channels that are not supported by STA
 */
int ieee80211_mbo_supp_op_cl_to_non_pref_chan_rpt(struct ieee80211_node *ni, u_int16_t countryCode)
{
    int i;
    ni->ni_supp_op_cl.num_chan_supported = 0;
    /**
     * Initializing array to false. The array index serves
     * as channel number. A false value indicates channel number
     * equal to the value of index of the slot is not supported.
     */
    for (i = 0; i < IEEE80211_CHAN_MAX;i++)
        ni->ni_supp_op_cl.channels_supported[i] = false;
    /**
     * marking true for those channels that are
     * supported by STA
     */
    for (i = 0; i < (ni->ni_supp_op_cl.num_of_supp_class); i++)
    {
        /**
         * Calling function that marks true for
         * those channels that are supported by the STA
         * as obtained from operating class
         */
        regdmn_get_channel_list_from_op_class(ni->ni_supp_op_cl.supp_class[i], ni);
    }
    return 1;
}

int
ieee80211_parse_op_class_ie(u_int8_t *frm, const struct ieee80211_frame *wh,
                            struct ieee80211_node *ni, u_int16_t countrycode)
{
    int i,opclass_num = 0;

    /**
     * Format of supported operating class IE
     * Elem ID:59( 1 byte )
     * Length: 2-253( 1 byte )
     * Current Operating class( 1 byte )
     * Supported operating classes( Variable )
     */
    opclass_num = ni->ni_supp_op_cl.num_of_supp_class = frm[1];
    ni->ni_supp_op_cl.curr_op_class = frm[2];

    if ( opclass_num ) {
        for (i = 0; i < opclass_num; i++) {
            ni->ni_supp_op_cl.supp_class[i] = frm[i+2];
        }
        ieee80211_mbo_supp_op_cl_to_non_pref_chan_rpt(ni,countrycode);
    }
    return 1;
}

/**
 * @brief Verify that the oce handle is valid
 *
 * @param [in] VAP  the handle to the
 *
 * @return true if handle is valid; otherwise false
 */

static INLINE bool ieee80211_oce_is_valid(const struct ieee80211vap *vap)
{
    return vap && vap->oce;
}

/**
 * @brief Initialize the OCE infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */
int ieee80211_oce_vattach (struct ieee80211vap *vap)
{
	ieee80211_oce_t oce;

	if (!ieee80211_oce_is_vap_valid(vap))
		return EINVAL;

	if (vap->oce)
		return EINPROGRESS;

	oce = (ieee80211_oce_t) OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(*oce), 0);
	if (oce == NULL)
		return -ENOMEM;

	OS_MEMZERO(oce, sizeof(*oce));
	oce->oce_osdev = vap->iv_ic->ic_osdev;
	oce->oce_ic = vap->iv_ic;
	oce->usr_assoc_min_rssi = OCE_ASSOC_MIN_RSSI_DEFAULT;
	oce->usr_assoc_retry_delay = OCE_ASSOC_RETRY_DELAY_DEFAULT;
	vap->oce = oce;

	QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: OCE Initialized \n", __func__);
	return EOK;
}

/**
 * @brief deint the OCE infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */
int ieee80211_oce_vdetach (struct ieee80211vap *vap)
{
	if (!ieee80211_oce_is_valid(vap))
		return EINVAL;

	if (vap->oce == NULL)
		return EINVAL;

	OS_FREE(vap->oce);
	vap->oce = NULL;

	QDF_PRINT_INFO(vap->iv_ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: OCE terminated\n", __func__);
	return EOK;
}

/**
 * set simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : config paramter
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */
int wlan_set_oce_param (wlan_if_t vap, u_int32_t param, u_int32_t val)
{
	int retv = EOK;
	ieee80211_oce_t oce = NULL;

	if (!ieee80211_oce_is_vap_valid(vap))
		return EINVAL;

	oce = vap->oce;

	switch (param) {
	case IEEE80211_OCE:
		if (val) {
			ieee80211_vap_oce_set(vap);
			/* Reset mgmt rate to enable OCE OOB rate */
			vap->iv_mgt_rate = 0;
		} else {
			ieee80211_vap_oce_clear(vap);
		}
		break;
	case IEEE80211_OCE_ASSOC_REJECT:
		if (ieee80211_vap_oce_is_set(vap)) {
			oce->usr_assoc_reject = val;
		} else {
			retv = EINVAL;
		}
		break;
	case IEEE80211_OCE_ASSOC_MIN_RSSI:
		if (ieee80211_vap_oce_is_set(vap)) {
			oce->usr_assoc_min_rssi = (u_int8_t) val;
		} else {
			retv = EINVAL;
		}
		break;
	case IEEE80211_OCE_ASSOC_RETRY_DELAY:
		if (ieee80211_vap_oce_is_set(vap)) {
			oce->usr_assoc_retry_delay = (u_int8_t) val;
		} else {
			retv = EINVAL;
		}
		break;
	case IEEE80211_OCE_WAN_METRICS:
		if (ieee80211_vap_oce_is_set(vap)) {
			oce->usr_wan_metrics = val;
			vap->iv_flags_ext2 |= IEEE80211_FEXT2_MBO;
		} else {
			retv = EINVAL;
		}
		break;
	default:
		retv = EINVAL;
		break;
	}

	return retv;
}

/**
 * get simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : paramter.
 * @return value of the parameter.
 */
u_int32_t wlan_get_oce_param (wlan_if_t vap, u_int32_t param)
{
	u_int32_t retv = 0;
	ieee80211_oce_t oce = NULL;

	if (!ieee80211_oce_is_vap_valid(vap))
		return EINVAL;

	oce = vap->oce;

	switch (param) {
	case IEEE80211_OCE:
		retv = ieee80211_vap_oce_is_set(vap);
		break;
	case IEEE80211_OCE_ASSOC_REJECT:
		retv = oce->usr_assoc_reject;
		break;
	case IEEE80211_OCE_ASSOC_MIN_RSSI:
		retv = oce->usr_assoc_min_rssi;
		break;
	case IEEE80211_OCE_ASSOC_RETRY_DELAY:
		retv = oce->usr_assoc_retry_delay;
		break;
	case IEEE80211_OCE_WAN_METRICS:
		retv = oce->usr_wan_metrics;
		break;
	default:
		retv = EINVAL;
		break;
	}

	return retv;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */
u_int8_t ieee80211_setup_oce_attrs (int f_type, struct ieee80211vap *vap, u_int8_t *frm, struct ieee80211_node *ni)
{
	ieee80211_oce_t oce = vap->oce;
	u_int8_t *start = frm;
	struct ieee80211_oce_cap *cap;
	struct ieee80211_oce_assoc_reject *reject;
	struct ieee80211_oce_wan_metrics *metrics;

	/* Attribute OCE_ATTRIB_CAP_INDICATION */
	cap = (struct ieee80211_oce_cap *) frm;
	cap->header.ie = OCE_ATTRIB_CAP_INDICATION;
	cap->header.len = sizeof (struct ieee80211_oce_cap) - 2;
	cap->ctrl_field =
		(OCE_CAP_REL_DEFAULT << OCE_CAP_RELEASE_SHIFT) |
		(0 << OCE_CAP_NON_OCE_AP_SHIFT);
	frm += sizeof (struct ieee80211_oce_cap);

	if ((f_type == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) ||
		(f_type == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)) {
		/* Attribute OCE_ATTRIB_RSSI_ASSOC_REJECT */
		if (oce->usr_assoc_reject && ni && (ni->ni_rssi < oce->usr_assoc_min_rssi)) {
			reject = (struct ieee80211_oce_assoc_reject *) frm;

			reject->header.ie = OCE_ATTRIB_RSSI_ASSOC_REJECT;
			reject->header.len = sizeof (struct ieee80211_oce_assoc_reject) - 2;
			reject->delta_rssi = oce->usr_assoc_min_rssi - ni->ni_rssi;
			reject->retry_delay = oce->usr_assoc_retry_delay;
			frm += sizeof (struct ieee80211_oce_assoc_reject);
		}
	} else {
		/* Attribute OCE_ATTRIB_REDUCED_WAN_METRICS */
		if (oce->usr_wan_metrics) {
			metrics = (struct ieee80211_oce_wan_metrics *) frm;

			metrics->header.ie = OCE_ATTRIB_REDUCED_WAN_METRICS;
			metrics->header.len = sizeof (struct ieee80211_oce_wan_metrics) - 2;
			metrics->avail_cap =
				(OCE_WAN_METRICS_CAP_DEFAULT << OCE_WAN_METRICS_DL_SHIFT) |
				(OCE_WAN_METRICS_CAP_DEFAULT << OCE_WAN_METRICS_UL_SHIFT);
			frm += sizeof (struct ieee80211_oce_wan_metrics);
		}
	}

	return (frm - start);
}
#else
/**
 * set configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : simple config paramaeter.
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */
int wlan_set_mbo_param(wlan_dev_t devhandle, ieee80211_device_param param, u_int32_t val)
{
    return EOK;
}

/**
 * get configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : config paramaeter.
 * @return value of the parameter.
 */
u_int32_t wlan_get_mbo_param(wlan_if_t vap, u_int32_t param)
{
    return EOK;
}

/**
 * @brief Initialize the MBO infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */

int ieee80211_mbo_vattach(struct ieee80211vap *vap)
{
    return EOK;
}

/**
 * @brief deint the MBO infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */

int ieee80211_mbo_vdetach(struct ieee80211vap *vap)
{

    return EOK;
}

/**
 * @brief setup MBO ie in Beacon infrastructure.
 *
 * @param [in] Vap to intialize beacon.
 *
 * @return frame pointer;
 *
 */

u_int8_t* ieee80211_setup_mbo_ie(int f_type, struct ieee80211vap *vap, u_int8_t *ie, struct ieee80211_node *ni)
{
    return ie;
}


/**
 * @brief Initialize the MBO infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */
int ieee80211_oce_vattach (struct ieee80211vap *vap)
{
	return EOK;
}

/**
 * @brief deint the MBO infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */
int ieee80211_oce_vdetach (struct ieee80211vap *vap)
{
	return EOK;
}

/**
 * set simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : config paramter
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */
int wlan_set_oce_param (wlan_if_t vap, u_int32_t param, u_int32_t val)
{
	return EOK;
}

/**
 * get simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : paramter.
 * @return value of the parameter.
 */
u_int32_t wlan_get_oce_param (wlan_if_t vap, u_int32_t param)
{
	return EOK;
}
#endif

/**
 * @brief Determine whether the VAP handle is valid,
 *        has a valid oce handle,
 *        is operating in a mode where OCE is relevant,
 *        and is not in the process of being deleted.
 *
 * @return true if the VAP is valid; otherwise false
 */
bool ieee80211_oce_is_vap_valid (struct ieee80211vap *vap)
{
	return (vap && (wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) &&
			!ieee80211_vap_deleted_is_set(vap));
}

/**
 * @brief Determine whether the VAP handle is valid,
 *        and OCE is enabled
 *
 * @return true if the VAP is valid and enabled; otherwise false
 */
bool ieee80211_vap_oce_check (struct ieee80211vap *vap)
{
	if (ieee80211_oce_is_vap_valid(vap) && vap->oce && ieee80211_vap_oce_is_set(vap))
		return true;
	else
		return false;
}

/**
 * @brief Determine whether assoc should be rejected or not,
 *        based on the RSSI of the received (Re)Assoc-Req and
 *        type of STA (OCE or non-OCE)
 *
 * @return true if the assoc is to be rejected; otherwise false
 */
bool ieee80211_vap_oce_assoc_reject (struct ieee80211vap *vap, struct ieee80211_node *ni)
{
	ieee80211_oce_t oce = vap->oce;

	if (oce->usr_assoc_reject) {
		if (ni && ni->ni_mbo.oce_sta && (ni->ni_rssi < oce->usr_assoc_min_rssi)) {
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
}
