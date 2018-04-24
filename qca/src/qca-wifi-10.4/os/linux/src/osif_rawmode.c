/*
* Copyright (c) 2014, Qualcomm Atheros, Inc..
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/


#include "osif_private.h"
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
#include <ol_rawmode_sim_api.h>
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include "osif_nss_wifiol_if.h"
#include "osif_nss_wifiol_vdev_if.h"
#endif

#if QCA_OL_SUPPORT_RAWMODE_TXRX
struct ieee80211vap *ol_ath_getvap(struct ol_txrx_vdev_t *vdev);
int
ol_tx_ll_umac_raw_process(struct net_device *dev, struct sk_buff **pskb)
{
    osif_dev  *osdev;
    struct sk_buff *slaveskb, *nextskb;
    int ret = 0;
    struct ieee80211vap *vap = NULL;

    /* Save pointer to first slave skb if present, for later freeing if unshare
     * fails. This is because we don't use the Linux frag_list mechanism and
     * hence cannot expect the OS to do the dropping for us.
     *
     * Also useful for similar error scenarios later.
     */
    slaveskb = qdf_nbuf_next(*pskb);

    /* Note for end system integrators: Please remove the below unshare and
     * related code if not applicable.
     */
    *pskb = qdf_nbuf_unshare(*pskb);

    if (*pskb == NULL) {
        goto bad;
    }

    osdev = ath_netdev_priv(dev);

#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION

    vap = ol_ath_getvap(osdev->iv_txrx_handle);
    if (vap->iv_rawmode_pkt_sim) {
        if (skb_headroom(*pskb) < dev->hard_header_len + dev->needed_headroom) {
            struct sk_buff *tmp = *pskb;

            *pskb = skb_realloc_headroom(tmp, dev->hard_header_len + dev->needed_headroom);
            qdf_nbuf_free(tmp);

            if (qdf_unlikely(*pskb == NULL)) {
                IEEE80211_DPRINTF(osdev->os_if, IEEE80211_MSG_OUTPUT,
                        "%s: cannot expand skb\n", __func__);
                goto bad;
            }
        }

        /* Zero out the cb part of the sk_buff, so it can be used by the simulation
         * if needed.
         */
        memset((*pskb)->cb, 0x0, sizeof((*pskb)->cb));

        ret = ol_rsim_tx_encap(osdev->iv_txrx_handle, pskb);

        if (ret == -1) {
            goto bad;
        } else if (ret == 1) {
            /* More nbufs to be accumulated for A-MSDU formation. */
            return 1;
        }
    }
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (osdev->nss_wifiol_ctx) {
        /*
         * Convert skb->next chained packets to skb fraglist
         *
         */
        osif_nss_vdev_tx_raw(osdev->iv_txrx_handle, pskb);
        if (osif_nss_ol_vap_xmit(osdev, *pskb)) {
            goto bad;
        }

        return 0;
    }
#endif

    osdev->iv_vap_send(osdev->iv_txrx_handle, *pskb);

    return 0;

bad:
    /* We handle free here instead of the caller, to save compute cycles for the
     * default non-raw case. */

    if (*pskb) {
        /* Re-save slave skb since master could change */
        slaveskb = qdf_nbuf_next(*pskb);
        qdf_nbuf_free(*pskb);
    }

    while (slaveskb) {
        nextskb = qdf_nbuf_next(slaveskb);
        qdf_nbuf_free(slaveskb);
        slaveskb = nextskb;
    }
    return -1;
}

/* Add any other required functionality here */

#endif /* QCA_OL_SUPPORT_RAWMODE_TXRX */
