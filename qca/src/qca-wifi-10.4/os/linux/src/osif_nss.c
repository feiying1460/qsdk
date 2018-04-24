/*
 **************************************************************************
 * Copyright (c) 2013, Qualcomm Atheros, Inc.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * osif_nss.c
 *
 * This file used for wifi redirect for NSS
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         23/sep/2013              Created
 */


#if  QCA_NSS_PLATFORM

#include "osif_private.h"
#include <wlan_opts.h>
#define OSIF_TO_NETDEV(_osif) (((osif_dev *)(_osif))->netdev)
#include <nss_api_if.h>

#if QCA_OL_GRO_ENABLE
/*
 * callback function that is registered with NSS
 * for the WLAN interface
 */
void osif_receive_from_nss(struct net_device *if_ctx, struct sk_buff *os_buf, struct napi_struct *napi)
{
	struct net_device *netdev;
	struct sk_buff *skb;
	osif_dev  *osifp;

	if(if_ctx == NULL) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_CRIT "%s , netdev is NULL, freeing skb", __func__);
		skb = (struct sk_buff *)os_buf;
		qdf_nbuf_free(skb);
		return;
	}

	netdev = (struct net_device *)if_ctx;
	dev_hold(netdev);
	osifp = netdev_priv(netdev);

	if (osifp->netdev != netdev) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_CRIT "%s , netdev incorrect, freeing skb", __func__);
		skb = (struct sk_buff *)os_buf;
		qdf_nbuf_free(skb);
		dev_put(netdev);
		return;
	}

	skb = (struct sk_buff *)os_buf;
	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, netdev);
        qdf_nbuf_count_dec(skb);
	napi_gro_receive(napi, skb);

	dev_put(netdev);
}
#endif /* QCA_OL_GRO_ENABLE */

/*
 * osif_pltfrm_create_vap
 *      Register vap with NSS
 */
void osif_pltfrm_create_vap(osif_dev *osif)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev  *osifp = (osif_dev *) osif;
    osifp->nss_redir_ctx = nss_create_virt_if(dev);
#if QCA_OL_GRO_ENABLE
    /* osifp->nssctx will be NULL for more than 16 VAPS */
    if (osifp->nss_redir_ctx != NULL) {
        nss_register_virt_if(osifp->nss_redir_ctx, osif_receive_from_nss, dev);
    }
#endif /* QCA_OL_GRO_ENABLE */
}

/*
 * osif_pltfrm_delete_vap
 *      Unregister vap with NSS
 */
void osif_pltfrm_delete_vap(osif_dev *osif)
{
    struct net_device *netdev;
    osif_dev  *osifp = (osif_dev *) osif;
    netdev = osifp->netdev;
    if(osifp->nss_redir_ctx) {
        /*
         * unregister_virt_if is taken care of inside the below nss API
         */
        nss_destroy_virt_if(osifp->nss_redir_ctx);
    }
}

/*
 * osif_send_to_nss
 *      Send packets to the nss driver
 */
extern void transcap_nwifi_to_8023(qdf_nbuf_t msdu);
void
osif_send_to_nss(os_if_t osif, struct sk_buff *skb, int nwifi)
{
    struct net_device *dev = OSIF_TO_NETDEV(osif);
    osif_dev  *osifp = (osif_dev *) osif;
    nss_tx_status_t nss_tx_status;

    if (!nwifi) {
        if (qdf_unlikely((((uint32_t)skb->data) & 3) != 2)) {
            /*
             * skb->data is not aligned to 2 byte boundary, send to stack directly
             */
            goto out;
        }
    }

    if(!osifp->nss_redir_ctx){
        goto out;
    }

    skb->next =NULL;
    if (skb_shared(skb)){
        goto out;
    }

    if (nwifi) {
        nss_tx_status = nss_tx_virt_if_rx_nwifibuf(osifp->nss_redir_ctx, skb) ;
    } else {
        nss_tx_status = nss_tx_virt_if_rxbuf(osifp->nss_redir_ctx, skb);
    }

    if (nss_tx_status == NSS_TX_SUCCESS) {
        return;
    }

    if (nss_tx_status == NSS_TX_FAILURE_QUEUE) {
        qdf_nbuf_free(skb);
        return;
    }

out:
    if (nwifi) {
        transcap_nwifi_to_8023(skb);
    }
    skb->protocol = eth_type_trans(skb, dev);
    skb->dev = dev;
    qdf_nbuf_count_dec(skb);
    netif_receive_skb(skb);
    return ;
}
EXPORT_SYMBOL(osif_send_to_nss);
#endif
