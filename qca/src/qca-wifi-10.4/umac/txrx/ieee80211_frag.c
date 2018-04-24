/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */
#include <ieee80211_txrx_priv.h>

#if UMAC_SUPPORT_TX_FRAG

/*
 * Fragment the frame according to the specified mtu.
 * The size of the 802.11 header (w/o padding) is provided
 * so we don't need to recalculate it.  We create a new
 * mbuf for each fragment and chain it through m_nextpkt;
 * we might be able to optimize this by reusing the original
 * packet's mbufs but that significantly more complicated.
 */
int
ieee80211_fragment(struct ieee80211vap *vap, wbuf_t wbuf0,
                   u_int hdrsize, u_int ciphdrsize, u_int mtu)
{
	struct ieee80211_frame *wh, *whf;
	wbuf_t wbuf, prev;
	u_int totalhdrsize, fragno, fragsize, off, remainder, payload;
        struct ieee80211com *ic = vap->iv_ic;

        if (ic->ic_flags & IEEE80211_F_DATAPAD)
            hdrsize = roundup(hdrsize, sizeof(u_int32_t));

	wh = (struct ieee80211_frame *)wbuf_header(wbuf0);
	/* NB: mark the first frag; it will be propagated below */
	wh->i_fc[1] |= IEEE80211_FC1_MORE_FRAG;
	totalhdrsize = hdrsize + ciphdrsize;
	fragno = 1;
	off = mtu - ciphdrsize;
	remainder = wbuf_get_pktlen(wbuf0) - off;
	prev = wbuf0;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT, "%s: wbuf0 %p, len %u nextpkt %p\n",
                      __func__, wbuf0, wbuf_get_len(wbuf0), wbuf_next(wbuf0));

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT, "%s: hdrsize %u, ciphdrsize %u mtu %u\n",
                      __func__, hdrsize, ciphdrsize, mtu);
	KASSERT(wbuf_next(wbuf0) == NULL, ("mbuf already chained?"));

	do {
		fragsize = totalhdrsize + remainder;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT, "%s: fragno %u off %u fragsize %u remainder %u\n",
                          __func__, fragno, off, fragsize, remainder);
		if (fragsize > mtu)
			fragsize = mtu;

        wbuf = wbuf_alloc(vap->iv_ic->ic_osdev, WBUF_TX_DATA, fragsize);
		if (wbuf == NULL)
			goto bad;

#if LMAC_SUPPORT_POWERSAVE_QUEUE
        if (wbuf_is_legacy_ps(wbuf0))
            wbuf_set_legacy_ps(wbuf);
#endif

		wbuf_set_priority(wbuf, wbuf_get_priority(wbuf0));
		wbuf_set_tid(wbuf, wbuf_get_tid(wbuf0));

                wbuf_set_node(wbuf, ieee80211_ref_node(wbuf_get_node(wbuf0)));
                /*
                 * reserve cipher size bytes to accommodate for the cipher size.
                 * wbuf_append followed by wbuf_pull is equivalent to skb_reserve.
                 */
                wbuf_append(wbuf, ciphdrsize);

        if (!wbuf_pull(wbuf,ciphdrsize))
			goto bad;

		/*
		 * Form the header in the fragment.  Note that since
		 * we mark the first fragment with the MORE_FRAG bit
		 * it automatically is propagated to each fragment; we
		 * need only clear it on the last fragment (done below).
		 */
		whf = (struct ieee80211_frame *)wbuf_header(wbuf);
		OS_MEMCPY(whf, wh, hdrsize);
		*(u_int16_t *)&whf->i_seq[0] |= htole16(
			(fragno & IEEE80211_SEQ_FRAG_MASK) <<
            IEEE80211_SEQ_FRAG_SHIFT);
		fragno++;

		payload = fragsize - totalhdrsize;
		wbuf_copydata(wbuf0, off, payload,
                      (u_int8_t *)whf + hdrsize);
		wbuf_set_pktlen(wbuf, hdrsize + payload);

		/* chain up the fragment */
        wbuf_set_next(prev,wbuf);
		prev = wbuf;

		/* deduct fragment just formed */
		remainder -= payload;
		off += payload;
	} while (remainder != 0);

	whf->i_fc[1] &= ~IEEE80211_FC1_MORE_FRAG;
	/* strip first mbuf now that everything has been copied */
	wbuf_trim(wbuf0, wbuf_get_pktlen(wbuf0) - (mtu-ciphdrsize));
	return 1;
bad:
	QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "CHH(%s): Bad Frag Return, remainder = %d\n",__func__,remainder);
	return 0;
}

#endif

#if UMAC_SUPPORT_RX_FRAG
static void 
ieee80211_timeout_fragments_iter(void *arg, struct ieee80211_node *ni)
{
    systime_t now;
    u_int32_t  lifetime = *(u_int32_t *)arg;
    wbuf_t wbuf = NULL;
    now = OS_GET_TIMESTAMP();
    if (OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 0, 1) == 1) {
        /* somebody is using the rxfrag */
        return;
    }
    if ((ni->ni_rxfrag[0] != NULL) &&
        (CONVERT_SYSTEM_TIME_TO_MS(now - ni->ni_rxfragstamp) >  lifetime)) {
        wbuf = ni->ni_rxfrag[0];
        ni->ni_rxfrag[0] = NULL;
    }

    if (wbuf) {
        wbuf_free(wbuf);
    }
    (void) OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 1, 0);
}

/*
 * Function to free all stale fragments
 */
void
ieee80211_timeout_fragments(struct ieee80211com *ic, u_int32_t lifetime)
{
    ieee80211_iterate_node(ic, ieee80211_timeout_fragments_iter,(void *) &lifetime);
}

wbuf_t
ieee80211_defrag(struct ieee80211_node *ni,
                 wbuf_t wbuf,
                 int hdrlen)
{
    struct ieee80211_frame *wh, *lwh = NULL;
    u_int16_t rxseq, last_rxseq;
    u_int8_t fragno, last_fragno;
    u_int8_t more_frag;
    int      tick_counter = 0;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    rxseq = le16_to_cpu(*(u_int16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
    fragno = le16_to_cpu(*(u_int16_t *)wh->i_seq) & IEEE80211_SEQ_FRAG_MASK;
    more_frag = wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG;

    /* Quick way out, if there's nothing to defragment */
    if (!more_frag && fragno == 0 && ni->ni_rxfrag[0] == NULL)
        return wbuf;

    /*
     * Remove frag to insure it doesn't get reaped by timer.
     */
    if (ni->ni_table == NULL) {
        /*
         * Should never happen.  If the node is orphaned (not in
         * the table) then input packets should not reach here.
         * Otherwise, a concurrent request that yanks the table
         * should be blocked by other interlocking and/or by first
         * shutting the driver down.  Regardless, be defensive
         * here and just bail
         */
        /* XXX need msg+stat */
        wbuf_free(wbuf);
        return NULL;
    }

    /*
     * Use this lock to make sure ni->ni_rxfrag[0] is
     * not freed by the timer process while we use it.
     */

    while (OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 0, 1) == 1) {
        /* busy wait; can be executed at IRQL <= DISPATCH_LEVEL */
        if (tick_counter++ > 100) {    // no more than 1ms
            break;
        }
        OS_DELAY(10);   
    }
    ni->ni_rxfragstamp = OS_GET_TIMESTAMP();
    
    /*
     * Validate that fragment is in order and
     * related to the previous ones.
     */
    if (ni->ni_rxfrag[0]) {
        lwh = (struct ieee80211_frame *) wbuf_header(ni->ni_rxfrag[0]);
        last_rxseq = le16_to_cpu(*(u_int16_t *)lwh->i_seq) >>
            IEEE80211_SEQ_SEQ_SHIFT;
        last_fragno = le16_to_cpu(*(u_int16_t *)lwh->i_seq) &
            IEEE80211_SEQ_FRAG_MASK;
        if (rxseq != last_rxseq
            || fragno != last_fragno + 1
            || (!IEEE80211_ADDR_EQ(wh->i_addr1, lwh->i_addr1))
            || (!IEEE80211_ADDR_EQ(wh->i_addr2, lwh->i_addr2))) {
            /*
             * Unrelated fragment or no space for it,
             * clear current fragments
             */
            wbuf_free(ni->ni_rxfrag[0]);
            ni->ni_rxfrag[0] = NULL;
        }
    }

    /* If this is the first fragment */
    if (ni->ni_rxfrag[0] == NULL) {
#ifdef ATH_SUPPORT_HTC
        struct ieee80211com *ic = ni->ni_ic;
        wbuf_t newbuf;
#endif
        if (fragno != 0) {      /* !first fragment, discard */
            /* XXX: msg + stats */
            wbuf_free(wbuf);
            (void) OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 1, 0);
            return NULL;
        }
#ifdef ATH_SUPPORT_HTC
        /* We need to allocate wbuf again */
        newbuf = wbuf_alloc(ic->ic_osdev, WBUF_USB_RX, MAX_TX_RX_PACKET_SIZE);
        if (newbuf == NULL) {
            wbuf_free(wbuf);
            wbuf = NULL;
            return wbuf;
        }
        wbuf_init(newbuf, wbuf_get_pktlen(wbuf));
        wbuf_copydata(wbuf, 0, wbuf_get_pktlen(wbuf), wbuf_header(newbuf));
        wbuf_free(wbuf);
        wbuf = newbuf;
#endif
        ni->ni_rxfrag[0] = wbuf;
    } else {
        ASSERT(fragno != 0);

        wbuf_pull(wbuf, hdrlen); /* strip the header of fragments other than the first one */
        wbuf_concat(ni->ni_rxfrag[0], wbuf);

        /* track last seqnum and fragno */
        *(u_int16_t *) lwh->i_seq = *(u_int16_t *) wh->i_seq;
    }

    if (more_frag) {
        /* More to come */
        wbuf = NULL;
    } else {
        /* Last fragment received, we're done! */
        wbuf = ni->ni_rxfrag[0];
        ni->ni_rxfrag[0] = NULL;

        /* clear fragno in the header because the frame we indicate
         * could include wireless header (for Native-WiFi). */
        *((u_int16_t *)lwh->i_seq) &= ~IEEE80211_SEQ_FRAG_MASK;
    }

    (void) OS_ATOMIC_CMPXCHG(&(ni->ni_rxfrag_lock), 1, 0);
    return wbuf;
}

#else /* UMAC_SUPPORT_RX_FRAG */

void
ieee80211_timeout_fragments(struct ieee80211com *ic, u_int32_t lifetime)
{
    /* NO OP */
}

#endif /* UMAC_SUPPORT_RX_FRAG */
 /* UMAC_SUPPORT_RX_FRAG */
