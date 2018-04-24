/*
 *
 * Copyright (c) 2017 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

/*
* QCN  module
*/
#if QCN_IE
#include "qcn.h"

/*
 * @ieee80211_qcn_fill_header() -adds headers to elements and subelements
 * @type:IE ID type
 * @len :length of IE
 *
 * Return:size of header added in bytes
 */

static inline u_int8_t ieee80211_qcn_fill_header(struct ieee80211_qcn_header *header,u_int8_t type,u_int8_t len)
{
    header->ie = type;
    header->len = len;
    return((u_int8_t)sizeof(struct ieee80211_qcn_header));
}

/*
 * @ieee80211_add_qcn_info_ie() - adds QCN IE
 * @ie:ie pointer
 * @vap :pointer to vap struct
 * @ie_len:pointer to length that will be returned
 * @bstm_reqinfo:pointer to bstm request struct

 * Return:New buffer pointer after the added IE
 */

u_int8_t *
ieee80211_add_qcn_info_ie(u_int8_t *ie,
                             struct ieee80211vap *vap, u_int16_t* ie_len,struct ieee80211_bstm_reqinfo_target *bstm_reqinfo)
{
    u_int8_t len = 0,*frm = NULL,*start = NULL;
    struct ieee80211_qcn_ie *qcn_ie = (struct ieee80211_qcn_ie *)ie;

    if(!qcn_ie)
        return ie;
    ieee80211_qcn_fill_header(&(qcn_ie->header),IEEE80211_ELEMID_VENDOR,0);
    qcn_ie->oui[0] = (QCA_OUI & 0xff);
    qcn_ie->oui[1] = ((QCA_OUI >> 8) & 0xff);
    qcn_ie->oui[2] = ((QCA_OUI >>16) & 0xff);
    qcn_ie->oui_type = QCN_OUI_TYPE;

    frm   = (u_int8_t *)&qcn_ie->opt_ie[0];
    start = frm;
    len   = ieee80211_setup_qcn_attrs(vap,&frm,bstm_reqinfo);
    qcn_ie->header.len = len + (sizeof(struct ieee80211_qcn_ie) - sizeof(struct ieee80211_qcn_header));
    /* return the length of this ie, including element ID and length field */
    *ie_len = qcn_ie->header.len +2;
    return (u_int8_t*)(start +len);
}

/*
 * @ieee80211_setup_ver_attr_ie() - adds QCN version attribute  IE
 * @frm:tracks location where to attach next sub-attribute
 *
 * Return:length of QCN version attribute
 */

u_int8_t  ieee80211_setup_ver_attr_ie(u_int8_t ** frm)
{

    struct ieee80211_qcn_ver_attr *ver_attr = (struct ieee80211_qcn_ver_attr*)(*frm);
    u_int8_t len = 0;

    len = ieee80211_qcn_fill_header(&(ver_attr->header),
                                    QCN_ATTRIB_VERSION,0);
    ver_attr->version     = QCN_VER_ATTR_VER;
    ver_attr->sub_version = QCN_VER_ATTR_SUBVERSION;
    ver_attr->header.len  =  sizeof(struct ieee80211_qcn_ver_attr) - len;

    *frm = (u_int8_t *)&ver_attr->opt_ie[0];
    len =  sizeof(struct ieee80211_qcn_ver_attr);
    return len;

}

/*
 * @ieee80211_setup_qcn_attrs() -   adds QCN  attributes
 * @frm:tracks location where to attach next sub-attribute
 * @bstm_reqinfo:points to structure for transition reason code passing
 *
 * Return:length of all QCN attributes added
 */

u_int8_t ieee80211_setup_qcn_attrs(struct ieee80211vap *vap,u_int8_t ** frm,struct ieee80211_bstm_reqinfo_target *bstm_reqinfo)
{
    u_int8_t len = 0;
    len += ieee80211_setup_ver_attr_ie(frm);
    /* send transaction reson code in btm request */
    if(bstm_reqinfo){
        len += ieee80211_setup_qcn_trans_reason_ie(vap,frm,bstm_reqinfo);
    }
    return len;
}

/*
 * @ieee80211_setup_qcn_ie_bstmreq_target() -  adds QCN  IE in BTM request packet
 * @vap:pointer to vap
 * @ie:location where we need to add ie
 * @bstm_reqinfo:points to structure for transition reason code passing
 * @macaddr:pointer to mac address of the node
 *
 * Return:pointer where next item should be populated
 */

u_int8_t*
ieee80211_setup_qcn_ie_bstmreq_target(struct ieee80211vap *vap, u_int8_t *ie,
                               struct ieee80211_bstm_reqinfo_target *bstm_reqinfo,
                               u_int8_t *macaddr)
{

    u_int8_t  *frm = NULL;
    u_int16_t ie_len;
    frm =  ieee80211_add_qcn_info_ie(ie,vap,&ie_len,bstm_reqinfo);
    return frm;
}


/*
 * @ieee80211_setup_qcn_trans_reason_ie() -  adds QCN  trans_reason sub-attribute
 * @vap:pointer to vap
 * @frm:tracks location where to attach next sub-attribute
 * @bstm_reqinfo:points to structure for transition reason code passing
 *
 * Return:length of attribute added
 */


u_int8_t
ieee80211_setup_qcn_trans_reason_ie(struct ieee80211vap *vap,u_int8_t **frm,struct ieee80211_bstm_reqinfo_target *bstm_reqinfo)
{
    struct ieee80211_qcn_transit_reason_code *trans_reason_code_ie = (struct ieee80211_qcn_transit_reason_code *)(*frm);
    u_int8_t len = 0;
    qcn_transition_reason_code trans_reason;
    trans_reason = (qcn_transition_reason_code)bstm_reqinfo->qcn_trans_reason;

    if (trans_reason <= QCN_TRANSITION_REASON_PREMIUM_AP) {
        len = ieee80211_qcn_fill_header(&(trans_reason_code_ie->header),QCN_ATTRIB_TRANSITION_REASON ,0 );
        trans_reason_code_ie->header.len  = (sizeof(struct ieee80211_qcn_transit_reason_code) - len);
        trans_reason_code_ie->reason_code = trans_reason;
        *frm = (u_int8_t *)&trans_reason_code_ie->opt_ie[0];
        len = sizeof(struct ieee80211_qcn_transit_reason_code);
    }
    return (u_int8_t)(len);

}

/*
 * @ieee80211_parse_qcnie() -  parse QCN  trans_reason sub-attribute
 * @frm:tracks location where to attach next sub-attribute
 * @wh:frame pointer
 * @ni:node pointer
 * @data: pointer for sending the version info to the caller

 * Return:0 on success , -1 on failure
 */
int
ieee80211_parse_qcnie(u_int8_t *frm, const struct ieee80211_frame *wh,
        struct ieee80211_node *ni,u_int8_t * data)
{

    u_int len = frm[1];
    u_int updated_len = 0;
    u_int slen,valid_id =1;
    u_int attribute_id;
    u_int attribute_len;
    if(len < QCN_IE_MIN_LEN) {
        IEEE80211_DISCARD_IE(ni->ni_vap,
                IEEE80211_MSG_ELEMID ,
                "QCN_IE", "too short, len %u", len);
        return -1;
    }


    if (len == QCN_IE_MIN_LEN) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_MLME," QCN_IE only one attribute present \n");
    }
    slen = len - 4;

    /*
     * Incrementing frm by 6 so that it will point to the qcn attribute id
     * 1 byte for element id
     * 1 byte for length
     * 3 bytes for QCN OUI
     * 1 byte for QCN OUI type
     */

    frm = frm + 6;
    /* if we get a call from probe request ,self node, populate the data and return */
    if(data) {
        attribute_id = *frm++;
        if(attribute_id == QCN_ATTRIB_VERSION) {
            attribute_len = *frm++;
            data[0] = *frm++; // version
            data[1] = *frm++; // sub-versoin
        }
    }
    else {
        while(slen > updated_len && valid_id)
        {
            attribute_id = *frm++;
            switch(attribute_id){
                case QCN_ATTRIB_VERSION:
                    attribute_len = *frm++;
                    ni->ni_qcn_version_flag = *frm++;
                    ni->ni_qcn_subver_flag = *frm++;
                    updated_len += attribute_len + 2;
                    break;
                case QCN_ATTRIB_TRANSITION_REJECTION:
                    attribute_len = *frm++;
                    ni->ni_qcn_tran_rej_code = *frm++;
                    updated_len += attribute_len + 2;
                    break;
                default:
                    printk("Warning:-QCN_IE attribute %d invalid or not defined yet \n",attribute_id);
                    valid_id = 0;
                    break;
            }
        }
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_MLME,"QCN_IE Version|0x%x|0x%x|, reject code |0x%x| \n", ni->ni_qcn_version_flag,ni->ni_qcn_subver_flag,ni->ni_qcn_tran_rej_code);
    }

return EOK;
}
#endif
