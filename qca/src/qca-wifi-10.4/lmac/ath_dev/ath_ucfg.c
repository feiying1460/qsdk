/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* This is the unified configuration file for iw, acfg and netlink cfg, etc. */
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/if_arp.h>       /* XXX for ARPHRD_ETHER */
#include <net/iw_handler.h>

#include <asm/uaccess.h>

#include "if_media.h"
#include "_ieee80211.h"
#include <osif_private.h>
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include <ieee80211_ioctl.h>
#include "ieee80211_rateset.h"
#include "ieee80211_vi_dbg.h"
#if ATH_SUPPORT_IBSS_DFS
#include <ieee80211_regdmn.h>
#endif

#include "if_athvar.h"
#include "if_athproto.h"

#include "ath_ucfg.h"

int ath_ucfg_setparam(struct ath_softc_net80211 *scn, int param, int value)
{
    struct ath_softc          *sc  =  ATH_DEV_TO_SC(scn->sc_dev);
    struct ath_hal            *ah =   sc->sc_ah;
    int retval  = 0;
    struct ieee80211com *ic = NET80211_HANDLE(sc->sc_ieee);

    /*
    ** Code Begins
    ** Since the parameter passed is the value of the parameter ID, we can call directly
    */
    if ( param & ATH_PARAM_SHIFT )
    {
        /*
        ** It's an ATH value.  Call the  ATH configuration interface
        */

        param -= ATH_PARAM_SHIFT;
        retval = scn->sc_ops->ath_set_config_param(scn->sc_dev,
                (ath_param_ID_t)param,
                &value);
    }
    else if ( param & SPECIAL_PARAM_SHIFT )
    {
        if ( param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_COUNTRY_ID) ) {
            if (sc->sc_ieee_ops->set_countrycode) {
                retval = sc->sc_ieee_ops->set_countrycode(
                        sc->sc_ieee, NULL, value, CLIST_NEW_COUNTRY);
            }
        } else if ( param  == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ASF_AMEM_PRINT) ) {
            asf_amem_status_print();
            if ( value ) {
                asf_amem_allocs_print(asf_amem_alloc_all, value == 1);
            }
        } else if (param  == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_DISP_TPC) ) {
            ath_hal_display_tpctables(ah);
        } else if (param  == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ENABLE_CH_144) ) {

            retval = (int) ath_hal_set_config_param(
                    ah, HAL_CONFIG_CH144, &value);

            if (sc->sc_ieee_ops->set_countrycode) {
                retval = sc->sc_ieee_ops->set_countrycode(
                        sc->sc_ieee, NULL, sc->sc_config.ath_countrycode, CLIST_NEW_COUNTRY);
            }
        } else  if (param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_REGDOMAIN)) {
            if (sc->sc_ieee_ops->set_regdomaincode) {
                retval = sc->sc_ieee_ops->set_regdomaincode(sc->sc_ieee, value);
            }
        }
        else if (param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ENABLE_SHPREAMBLE) ) {
            if (value) {
                scn->sc_ic.ic_caps |= IEEE80211_C_SHPREAMBLE;
            } else {
                scn->sc_ic.ic_caps &= ~IEEE80211_C_SHPREAMBLE;
            }
        } else if (param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ENABLE_MAC_REQ) ) {
            if ( !TAILQ_EMPTY(&ic->ic_vaps) ) {
                QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: We do not support this if there are VAPs present\n",__func__);
                retval = -EBUSY;
            } else {
                scn->macreq_enabled = value;
                if (sc->sc_hasbmask) {
                    /* reset the bssid mask before setting the new mask */
                    OS_MEMSET(sc->sc_bssidmask, 0xff, sizeof(sc->sc_bssidmask));
                    if (scn->macreq_enabled)
                        ATH_SET_VAP_BSSID_MASK_ALTER(sc->sc_bssidmask);
                    else
                        ATH_SET_VAP_BSSID_MASK(sc->sc_bssidmask);

                    ath_hal_setbssidmask(sc->sc_ah, sc->sc_bssidmask);
                }
            }
        } else
            retval = -EOPNOTSUPP;
    }
    else
    {
        retval = (int) ath_hal_set_config_param(
                ah, (HAL_CONFIG_OPS_PARAMS_TYPE)param, &value);
    }

    return retval;
}
EXPORT_SYMBOL(ath_ucfg_setparam);

int ath_ucfg_getparam(struct ath_softc_net80211 *scn, int param, int *val)
{
    struct ath_softc          *sc   = ATH_DEV_TO_SC(scn->sc_dev);
    struct ath_hal            *ah   = sc->sc_ah;
    int retval  = 0;

    /*
    ** Code Begins
    ** Since the parameter passed is the value of the parameter ID, we can call directly
    */
    if ( param & ATH_PARAM_SHIFT )
    {
        /*
        ** It's an ATH value.  Call the  ATH configuration interface
        */

        param -= ATH_PARAM_SHIFT;
        if ( scn->sc_ops->ath_get_config_param(scn->sc_dev,(ath_param_ID_t)param,val) )
        {
            retval = -EOPNOTSUPP;
        }
    }
    else if ( param & SPECIAL_PARAM_SHIFT )
    {
        if ( param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_COUNTRY_ID) ) {
            HAL_COUNTRY_ENTRY         cval;

            scn->sc_ops->get_current_country(scn->sc_dev, &cval);
            val[0] = cval.countryCode;
        } else if ( param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ENABLE_CH_144) ) {
            if ( !ath_hal_get_config_param(ah, HAL_CONFIG_CH144, val) )
            {
                retval = -EOPNOTSUPP;
            }
        } else if ( param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_REGDOMAIN) ) {
            val[0] = scn->sc_ops->get_regdomain(scn->sc_dev);
        } else if ( param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ENABLE_SHPREAMBLE) ) {
            val[0] = (scn->sc_ic.ic_caps & IEEE80211_C_SHPREAMBLE) != 0;
        } else if ( param == (SPECIAL_PARAM_SHIFT | SPECIAL_PARAM_ENABLE_SHSLOT) ) {
            val[0] = IEEE80211_IS_SHSLOT_ENABLED(&scn->sc_ic) ? 1 : 0;
        } else {
            retval = -EOPNOTSUPP;
        }
    }
    else
    {
        if ( !ath_hal_get_config_param(ah, (HAL_CONFIG_OPS_PARAMS_TYPE)param, val) )
        {
            retval = -EOPNOTSUPP;
        }
    }

    return retval;
}
EXPORT_SYMBOL(ath_ucfg_getparam);

int ath_ucfg_set_countrycode(struct ath_softc_net80211 *scn, char *cntry)
{
    struct ath_softc *sc  = ATH_DEV_TO_SC(scn->sc_dev);
    int retval;

    if (sc->sc_ieee_ops->set_countrycode) {
        retval = sc->sc_ieee_ops->set_countrycode(sc->sc_ieee, cntry, 0, CLIST_NEW_COUNTRY);
    } else {
        retval = -EOPNOTSUPP;
    }

    return retval;
}
EXPORT_SYMBOL(ath_ucfg_set_countrycode);

void ath_ucfg_get_country(struct ath_softc_net80211 *scn, char *str)
{
    HAL_COUNTRY_ENTRY cval;

    /*
    ** Code Begins
    */
    scn->sc_ops->get_current_country(scn->sc_dev, &cval);
    str[0] = cval.iso[0];
    str[1] = cval.iso[1];
    str[2] = cval.iso[2];
    str[3] = 0;
}
EXPORT_SYMBOL(ath_ucfg_get_country);

#if ATH_SUPPORT_DSCP_OVERRIDE
void ath_ucfg_set_dscp_tid_map(struct ath_softc_net80211 *scn, u_int8_t tos, u_int8_t tid)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    sc->sc_ieee_ops->set_dscp_tid_map(sc->sc_ieee, tos, tid);
}
EXPORT_SYMBOL(ath_ucfg_set_dscp_tid_map);

int ath_ucfg_get_dscp_tid_map(struct ath_softc_net80211 *scn, u_int8_t tos)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    return sc->sc_ieee_ops->get_dscp_tid_map(sc->sc_ieee, tos);
}
EXPORT_SYMBOL(ath_ucfg_get_dscp_tid_map);
#endif

int ath_ucfg_set_mac_address(struct ath_softc_net80211 *scn, char *addr)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct net_device *dev = scn->sc_osdev->netdev;
    struct sockaddr sa;
    int retval;

    if ( !TAILQ_EMPTY(&ic->ic_vaps) ) {
        retval = -EBUSY; //We do not set the MAC address if there are VAPs present
    } else {
        IEEE80211_ADDR_COPY(&sa.sa_data, addr);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
        retval = dev->netdev_ops->ndo_set_mac_address(dev, &sa);
#else
        retval = dev->set_mac_address(dev, &sa);
#endif
    }

    return retval;
}
EXPORT_SYMBOL(ath_ucfg_set_mac_address);

#if UNIFIED_SMARTANTENNA
int ath_ucfg_set_smartantenna_param(struct ath_softc_net80211 *scn, char *val)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    return (sc->sc_ieee_ops->smart_ant_setparam(sc->sc_ieee, val));
}
EXPORT_SYMBOL(ath_ucfg_set_smartantenna_param);

int ath_ucfg_get_smartantenna_param(struct ath_softc_net80211 *scn, char *val)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(scn->sc_dev);

    return sc->sc_ieee_ops->smart_ant_getparam(sc->sc_ieee, val);
}
EXPORT_SYMBOL(ath_ucfg_get_smartantenna_param);
#endif

int ath_ucfg_diag(struct ath_softc_net80211 *scn, struct ath_diag *ad)
{
    struct ath_hal *ah = (ATH_DEV_TO_SC(scn->sc_dev))->sc_ah;
    u_int id = ad->ad_id & ATH_DIAG_ID;
    void *indata = NULL;
    void *outdata = NULL;
    u_int32_t insize = ad->ad_in_size;
    u_int32_t outsize = ad->ad_out_size;
    int error = 0;
    if (ad->ad_id & ATH_DIAG_IN) {
        /*
         * Copy in data.
         */
        indata = kmalloc(insize, GFP_KERNEL);
        if (indata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
        if (__xcopy_from_user(indata, ad->ad_in_data, insize)) {
            error = -EFAULT;
            goto bad;
        }
    }
    if (ad->ad_id & ATH_DIAG_DYN) {
        /*
         * Allocate a buffer for the results (otherwise the HAL
         * returns a pointer to a buffer where we can read the
         * results).  Note that we depend on the HAL leaving this
         * pointer for us to use below in reclaiming the buffer;
         * may want to be more defensive.
         */
        outdata = kmalloc(outsize, GFP_KERNEL);
        if (outdata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
    }
    if (ath_hal_getdiagstate(ah, id, indata, insize, &outdata, &outsize)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "alloc size = %d, new = %d\n", ad->ad_out_size, outsize);
        if (outsize < ad->ad_out_size)
            ad->ad_out_size = outsize;
        if (outdata &&
                _copy_to_user(ad->ad_out_data, outdata, ad->ad_out_size))
            error = -EFAULT;
    } else {
        error = -EINVAL;
    }
bad:
    if ((ad->ad_id & ATH_DIAG_IN) && indata != NULL)
        kfree(indata);
    if ((ad->ad_id & ATH_DIAG_DYN) && outdata != NULL)
        kfree(outdata);
    return error;

}
EXPORT_SYMBOL(ath_ucfg_diag);

#if defined(ATH_SUPPORT_DFS) || defined(ATH_SUPPORT_SPECTRAL)
int ath_ucfg_phyerr(struct ath_softc_net80211 *scn, struct ath_diag *ad)
{
    void *indata=NULL;
    void *outdata=NULL;
    int error = -EINVAL;
    u_int32_t insize = ad->ad_in_size;
    u_int32_t outsize = ad->ad_out_size;
    u_int id= ad->ad_id & ATH_DIAG_ID;
    struct ieee80211com *ic = &scn->sc_ic;

    /*
       EV904010 -- Make sure there is a VAP on the interface
       before the request is processed
       */
    if ((ATH_DEV_TO_SC(scn->sc_dev))->sc_nvaps == 0) {
        return -EINVAL;
    }

    if (ad->ad_id & ATH_DIAG_IN) {
        /*
         * Copy in data.
         */
        indata = OS_MALLOC(scn->sc_osdev,insize, GFP_KERNEL);
        if (indata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
        if (__xcopy_from_user(indata, ad->ad_in_data, insize)) {
            error = -EFAULT;
            goto bad;
        }
        id = id & ~ATH_DIAG_IN;
    }
    if (ad->ad_id & ATH_DIAG_DYN) {
        /*
         * Allocate a buffer for the results (otherwise the HAL
         * returns a pointer to a buffer where we can read the
         * results).  Note that we depend on the HAL leaving this
         * pointer for us to use below in reclaiming the buffer;
         * may want to be more defensive.
         */
        outdata = OS_MALLOC(scn->sc_osdev, outsize, GFP_KERNEL);
        if (outdata == NULL) {
            error = -ENOMEM;
            goto bad;
        }
        id = id & ~ATH_DIAG_DYN;
    }

#if 1 // UMACDFS: Move this call to net80211 layer as DFS moved out of lmac. ATH_SUPPORT_DFS
    error = ic->ic_dfs_control(
            ic, id, indata, insize, outdata, &outsize);
#endif

#if ATH_SUPPORT_SPECTRAL
    if (error ==  -EINVAL ) {
        error = scn->sc_ops->ath_spectral_control(
                scn->sc_dev, id, indata, insize, outdata, &outsize);
    }
#endif

    if (outsize < ad->ad_out_size)
        ad->ad_out_size = outsize;

    if (outdata &&
            _copy_to_user(ad->ad_out_data, outdata, ad->ad_out_size))
        error = -EFAULT;
bad:
    if ((ad->ad_id & ATH_DIAG_IN) && indata != NULL)
        OS_FREE(indata);
    if ((ad->ad_id & ATH_DIAG_DYN) && outdata != NULL)
        OS_FREE(outdata);

    return error;
}
EXPORT_SYMBOL(ath_ucfg_phyerr);
#endif
