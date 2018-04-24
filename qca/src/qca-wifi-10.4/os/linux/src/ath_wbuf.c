/*
 * Copyright (c) 2010, Atheros Communications Inc.
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



#include "ath_internal.h"
#include <osdep.h>
#include <wbuf.h>


#define MIN_HEAD_ROOM  64
#define NBUF_ALLOC_FAIL_LIMIT 100

#ifndef ADF_SUPPORT
#if !LIMIT_RXBUF_LEN_4K
static struct sk_buff *
ath_alloc_skb(u_int size, u_int align)
{
    struct sk_buff *skb;
    u_int off;

    skb = dev_alloc_skb(size + align - 1);
    if (skb != NULL) {
        off = ((unsigned long) skb->data) & (align - 1);
        if (off != 0)
            skb_reserve(skb, align - off);
    }
    return skb;
}
#endif

struct sk_buff *
ath_rxbuf_alloc(struct ath_softc *sc, u_int32_t len)
{
    struct sk_buff *skb;
    struct net_device *dev = sc->sc_osdev->netdev;

#if USE_MULTIPLE_BUFFER_RECV
    size_t  original_size = len;
#endif
    if (sc->sc_opmode == HAL_M_MONITOR) {
        u_int off;
        /*
         * Allocate buffer for monitor mode with space for the
         * wlan-ng style physical layer header at the start.
         */
        skb = dev_alloc_skb(len +
                            sizeof(wlan_ng_prism2_header) +
                            sc->sc_cachelsz - 1);
        if (skb == NULL) {
            qdf_print(
                    "%s: skbuff alloc of size %zu failed\n",
                    __func__,
                    len
                    + sizeof(wlan_ng_prism2_header)
                    + sc->sc_cachelsz -1);
            return NULL;
        }
        /*
         * Reserve space for the Prism header.
         */
        skb_reserve(skb, sizeof(wlan_ng_prism2_header));
        /*
         * Align to cache line.
         */
        off = ((unsigned long) skb->data) & (sc->sc_cachelsz - 1);
        if (off != 0)
            skb_reserve(skb, sc->sc_cachelsz - off);
#if LIMIT_RXBUF_LEN_4K
        if (unlikely(skb_headroom(skb) < NET_SKB_PAD)) {
            dump_stack();
            panic("%s: skb (skb->data=%p) doesn't have required headroom, "
                    "has %d bytes (len=%d+%d)\n", __func__, skb->data,
                    skb_headroom(skb), len, sizeof(wlan_ng_prism2_header));
        } else {
            skb->data -= NET_SKB_PAD;
            skb->tail = skb->data;
        }
#endif
    } else {
        ASSERT(sizeof(struct ieee80211_cb) + sizeof(void *) <= sizeof(skb->cb));
        /*
         * Cache-line-align.  This is important (for the
         * 5210 at least) as not doing so causes bogus data
         * in rx'd frames.
         */
#if LIMIT_RXBUF_LEN_4K
        skb = dev_alloc_skb(len - NET_SKB_PAD);
#else
        skb = ath_alloc_skb(len, sc->sc_cachelsz);
#endif
        if (skb == NULL) {
            qdf_print(
                    "%s: skbuff alloc of size %u failed\n",
                    __func__, len);
			return NULL;
        }
#if LIMIT_RXBUF_LEN_4K
        if (unlikely((u_int32_t)(skb->data) & (sc->sc_cachelsz - 1))) {
            dump_stack();
            panic("%s: skb->data=%p (skb->head=%p) is not aligned "
                    "to %d bytes (len=%d)\n", __func__, skb->data, skb->head,
                    sc->sc_cachelsz, len);
        }
        if (unlikely(skb_headroom(skb) < NET_SKB_PAD)) {
            dump_stack();
            panic("%s: skb (skb->data=%p) doesn't have required headroom, "
                    "has %d bytes (len=%d)\n", __func__, skb->data,
                    skb_headroom(skb), len);
        } else {
            skb->data -= NET_SKB_PAD;
            skb->tail = skb->data;
        }
#endif
    }

    skb->dev = dev;

    /*
     * setup rx context in skb
     * XXX: this violates the rule of ath_dev,
     * which is supposed to be protocol independent.
     */
    ((struct ieee80211_cb *)skb->cb)->context =
        &(((struct ieee80211_cb *)skb->cb)[1]);


#if USE_MULTIPLE_BUFFER_RECV
    ((struct ieee80211_cb *)skb->cb)->buf_size=
        original_size;
#endif

    return skb;
}
EXPORT_SYMBOL(ath_rxbuf_alloc);

struct sk_buff *
wbuf_alloc(osdev_t os_handle, enum wbuf_type type, u_int32_t len)
{
    const u_int align = sizeof(u_int32_t);
    struct ieee80211_cb *cb;
    struct sk_buff *skb;
    u_int buflen;
    if ((type == WBUF_TX_DATA) || (type == WBUF_TX_MGMT) ||
            (type == WBUF_TX_BEACON) || (type == WBUF_TX_INTERNAL) ||
            (type == WBUF_TX_CTL))
        buflen = roundup(len+MIN_HEAD_ROOM, 4);
    else
        buflen = roundup(len, 4);
    skb = dev_alloc_skb(buflen + align-1);
    if (skb != NULL)
    {
        u_int off = ((unsigned long) skb->data) & (align - 1);
        if (off != 0)
            skb_reserve(skb, align - off);

        cb = (
        struct ieee80211_cb *)skb->cb;
        cb->ni = NULL;
        cb->flags = 0;
        cb->type = type;
#if defined(ATH_SUPPORT_P2P) || (defined(ATH_SUPPORT_DEFERRED_NODE_CLEANUP) && ATH_SUPPORT_DEFERRED_NODE_CLEANUP !=0)
        cb->complete_handler = NULL;
        cb->complete_handler_arg = NULL;
#endif
        if (type == WBUF_TX_DATA || type == WBUF_TX_MGMT || type ==
                WBUF_TX_BEACON || type == WBUF_TX_INTERNAL || type ==
                WBUF_TX_CTL)
            skb_reserve(skb, MIN_HEAD_ROOM);
    }
    return skb;
}
EXPORT_SYMBOL(wbuf_alloc);

void
wbuf_release(osdev_t os_handle, struct sk_buff *skb)
{
    qdf_nbuf_free(skb);
}
EXPORT_SYMBOL(wbuf_release);

int wbuf_start_dma(wbuf_t wbuf, sg_t *sg, u_int32_t n_sg, void *arg)
{
    return ath_tx_start_dma(wbuf, sg, n_sg, arg);
}


int
__wbuf_map_sg(osdev_t osdev, struct sk_buff *skb, dma_addr_t *pa, void *arg)
{
    struct scatterlist sg;
    int ret;

    *pa = bus_map_single(osdev, skb->data, UNI_SKB_END_POINTER(skb) - skb->data, BUS_DMA_TODEVICE);

    /* setup S/G list */
    memset(&sg, 0, sizeof(struct scatterlist));
    sg_dma_address(&sg) = *pa;
    sg_dma_len(&sg) = skb->len;

    ret = wbuf_start_dma(skb, &sg, 1, arg);
    if (ret) {
        /*
         * NB: common code doesn't tail drop frame
         * because it's not allowed in NDIS 6.0.
         * For Linux, we have to do it here.
         */
        bus_unmap_single(osdev, *pa, UNI_SKB_END_POINTER(skb) - skb->data, BUS_DMA_TODEVICE);
    }

    return ret;
}
EXPORT_SYMBOL(__wbuf_map_sg);

void
__wbuf_unmap_sg(osdev_t osdev, struct sk_buff *skb, dma_addr_t *pa)
{
    bus_unmap_single(osdev, *pa, UNI_SKB_END_POINTER(skb) - skb->data, BUS_DMA_TODEVICE);
}
EXPORT_SYMBOL(__wbuf_unmap_sg);

dma_addr_t
__wbuf_map_single_tx(osdev_t osdev, struct sk_buff *skb, int direction, dma_addr_t *pa)
{
    /*
     * NB: do NOT use skb->len, which is 0 on initialization.
     * Use skb's entire data area instead.
     */
    *pa = bus_map_single(osdev, skb->data, UNI_SKB_END_POINTER(skb) - skb->data, direction);

    return *pa;
}
void
__wbuf_uapsd_update(struct sk_buff *skb)
{
    /* DO NOTHING */
}

#ifdef ATH_SUPPORT_HTC

__wbuf_t __wbuf_realloc_hdrspace(__wbuf_t wbuf, u_int16_t size)
{
#if 1
    if(pskb_expand_head(wbuf, size - skb_headroom(wbuf), 0, GFP_ATOMIC)){
        qdf_nbuf_free(wbuf);
        wbuf = NULL;
    }
    return wbuf;
#else
    __wbuf_t new_buf;

    skb_unshare(wbuf, GFP_ATOMIC);
    new_buf = skb_realloc_headroom(wbuf, size);

    qdf_nbuf_free(wbuf);

    return new_buf;
#endif
}

int __wbuf_cat(__wbuf_t dst, __wbuf_t src)
{
    ASSERT(0);
    return 0;
}
#endif /* end of #ifdef ATH_SUPPORT_HTC */

#else  // below APIs implementation using ADF

qdf_nbuf_t
ath_rxbuf_alloc(struct ath_softc *sc, u_int32_t len)
{
    qdf_nbuf_t nbf;
    struct net_device *dev = sc->sc_osdev->netdev;
    static u_int32_t nbuf_fail_limit_print = 0;

    if (sc->sc_opmode == HAL_M_MONITOR) {
        /*
         * Allocate buffer for monitor mode with space for the
         * wlan-ng style physical layer header at the start.
         */
        nbf = qdf_nbuf_alloc(NULL, len + sizeof(wlan_ng_prism2_header),
                             sizeof(wlan_ng_prism2_header),
                             sc->sc_cachelsz, FALSE);
        if (nbf == NULL)
        {
            if(!(nbuf_fail_limit_print % NBUF_ALLOC_FAIL_LIMIT))
            {
                qdf_print(
                        "%s: nbuf alloc of size %zu failed\n",
                        __func__,
                        len
                        + sizeof(wlan_ng_prism2_header)
                        + sc->sc_cachelsz -1);
            }
            nbuf_fail_limit_print++;
            return NULL;
        }
#if LIMIT_RXBUF_LEN_4K
        if (unlikely(qdf_nbuf_headroom(nbf) < NET_SKB_PAD)) {
            dump_stack();
            panic("%s: nbf (nbf->data=%p) doesn't have required headroom, "
                    "has %d bytes (len=%d+%d)\n", __func__, nbf->data,
                    qdf_nbuf_headroom(nbf), len, sizeof(wlan_ng_prism2_header));
        } else {
            nbf->data -= NET_SKB_PAD;
            nbf->tail = nbf->data;
        }
#endif
    } else {
        ASSERT(sizeof(struct ieee80211_cb) + sizeof(void *) <= sizeof(nbf->cb));
        /*
         * Cache-line-align.  This is important (for the
         * 5210 at least) as not doing so causes bogus data
         * in rx'd frames.
         */
#if LIMIT_RXBUF_LEN_4K
        nbf = qdf_nbuf_alloc(NULL, len - NET_SKB_PAD, 0, 0, FALSE);
#else
        nbf = qdf_nbuf_alloc(NULL, len, 0, sc->sc_cachelsz, FALSE);
#endif
        if (nbf == NULL)
        {
            if(!(nbuf_fail_limit_print % NBUF_ALLOC_FAIL_LIMIT))
            {
                qdf_print(
                        "%s: nbuf alloc of size %u failed\n",
                        __func__, len);
            }
            nbuf_fail_limit_print++;
            return NULL;
        }
#if LIMIT_RXBUF_LEN_4K
        if (unlikely((u_int32_t)(nbf->data) & (sc->sc_cachelsz - 1))) {
            dump_stack();
            panic("%s: nbf->data=%p (nbf->head=%p) is not aligned "
                    "to %d bytes (len=%d)\n", __func__, nbf->data, nbf->head,
                    sc->sc_cachelsz, len);
        }
        if (unlikely(qdf_nbuf_headroom(nbf) < NET_SKB_PAD)) {
            dump_stack();
            panic("%s: nbf (nbf->data=%p) doesn't have required headroom, "
                    "has %d bytes (len=%d)\n", __func__, nbf->data,
                    qdf_nbuf_headroom(nbf), len);
        } else {
            nbf->data -= NET_SKB_PAD;
            nbf->tail = nbf->data;
        }
#endif
    }

    nbf->dev = dev;

    /*
     * setup rx context in nbuf
     * XXX: this violates the rule of ath_dev,
     * which is supposed to be protocol independent.
     */
    N_CONTEXT_SET(nbf, &((struct ieee80211_cb *)(nbf->cb))[1]);

    return nbf;
}
EXPORT_SYMBOL(ath_rxbuf_alloc);

qdf_nbuf_t
wbuf_alloc(osdev_t os_handle, enum wbuf_type type, u_int32_t len)
{
    const u_int align = sizeof(u_int32_t);
    qdf_nbuf_t  nbf;
    u_int buflen, reserve;
    if ((type == WBUF_TX_DATA) || (type == WBUF_TX_MGMT) ||
            (type == WBUF_TX_BEACON) || (type == WBUF_TX_INTERNAL)
            || (type == WBUF_TX_CTL)) {
        reserve = MIN_HEAD_ROOM;
        buflen = roundup(len+MIN_HEAD_ROOM, 4);
    } else {
        reserve = 0;
        buflen = roundup(len, 4);
    }
    nbf = qdf_nbuf_alloc(NULL, buflen, 0, align, FALSE);
    if (nbf != NULL)
    {
        N_NODE_SET(nbf, NULL);
        N_FLAG_KEEP_ONLY(nbf, 0);
        N_TYPE_SET(nbf, type);
        N_COMPLETE_HANDLER_SET(nbf, NULL);
        N_COMPLETE_HANDLER_ARG_SET(nbf, NULL);
#if defined(ATH_SUPPORT_P2P)
        N_COMPLETE_HANDLER_SET(nbf, NULL);
        N_COMPLETE_HANDLER_ARG_SET(nbf, NULL);
#endif  /* ATH_SUPPORT_P2P */
        if (reserve)
            qdf_nbuf_reserve(nbf, reserve);
    }
    return nbf;
}
EXPORT_SYMBOL(wbuf_alloc);

void
wbuf_release(osdev_t os_handle, qdf_nbuf_t nbf)
{
    qdf_nbuf_free(nbf);
}

dma_addr_t
__wbuf_map_single_tx(osdev_t osdev, struct sk_buff *skb, int direction, dma_addr_t *pa)
{
    /*
     * NB: do NOT use skb->len, which is 0 on initialization.
     * Use skb's entire data area instead.
     */
    *pa = bus_map_single(osdev, skb->data, UNI_SKB_END_POINTER(skb) - skb->data, direction);

    return *pa;
}

void
__wbuf_uapsd_update(qdf_nbuf_t nbf)
{
    /* DO NOTHING */
}

#if ATH_PERF_PWR_OFFLOAD
EXPORT_SYMBOL(__wbuf_map_single);
EXPORT_SYMBOL(__wbuf_map_single_tx);
EXPORT_SYMBOL(__wbuf_unmap_single);
#endif  /* ATH_PERF_PWR_OFFLOAD */

#endif
