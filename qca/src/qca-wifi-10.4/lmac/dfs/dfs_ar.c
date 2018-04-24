/*
 * Copyright (c) 2002-2010, Atheros Communications Inc.
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
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "dfs.h"
#include <ieee80211_var.h>
#ifdef ATH_SUPPORT_DFS

#define UPDATE_TOP_THREE_PEAKS(_histo, _peakPtrList, _currWidth) { \
	if ((_histo)[(_peakPtrList)[0]] < (_histo)[(_currWidth)]) {	\
		(_peakPtrList)[2] = (_currWidth != (_peakPtrList)[1]) ?	\
					(_peakPtrList)[1] : (_peakPtrList)[2];  \
		(_peakPtrList)[1] = (_peakPtrList)[0]; \
		(_peakPtrList)[0] = (_currWidth); \
	} else if ((_currWidth != (_peakPtrList)[0])	\
			&& ((_histo)[(_peakPtrList)[1]] < (_histo)[(_currWidth)])) { \
		(_peakPtrList)[2] = (_peakPtrList)[1]; \
		(_peakPtrList)[1] = (_currWidth);      \
	} else if ((_currWidth != (_peakPtrList)[1])   \
			&& (_currWidth != (_peakPtrList)[0])  \
			&& ((_histo)[(_peakPtrList)[2]] < (_histo)[(_currWidth)])) { \
		(_peakPtrList)[2] = (_currWidth);  \
	} \
}
void ath_ar_enable(struct ath_dfs *dfs)
{
#if 0 //UMACDFS: TODO: Looks lke obsolete
	struct ath_dfs *dfs=ic->ic_dfs;
	struct dfs_ar_state *ar;
	struct ieee80211_channel *chan= &sc->sc_curchan;
	HAL_PHYERR_PARAM pe;
	u_int32_t rfilt=0;

	if (dfs == NULL) {
		DFS_DPRINTK(ic, ATH_DEBUG_DFS, "%s: ic_dfs is NULL\n",
			__func__);
		return;
	}

	ar = (struct dfs_ar_state *) &dfs->dfs_ar_state;
	if (dfs->dfs_proc_phyerr & (DFS_RADAR_EN | DFS_AR_EN)) {
		if (IEEE80211_IS_CHAN_108G(chan)) {
			/* We are in turbo G, so enable AR */
			DFS_DPRINTK(ic, ATH_DEBUG_DFS, "%s: Enabling AR\n", __func__);
			dfs_reset_ar(ic);
			ar->ar_radarrssi = DFS_AR_RADAR_RSSI_THR;
			rfilt = ath_hal_getrxfilter(sc->sc_ah);
			pe.pe_firpwr = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_height = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_prssi = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_inband = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_relpwr = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_maxlen = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_relstep = HAL_PHYERR_PARAM_NOVAL;
			pe.pe_usefir128 = 0;
			pe.pe_blockradar = 0;
			pe.pe_enmaxrssi = 0;
			pe.pe_rrssi = ar->ar_radarrssi;
			ath_hal_enabledfs(sc->sc_ah, &pe);
			/* Enable strong signal fast antenna diversity since accurate 
			 * 1-2us radar
			 * detection is not important for AR anyways.
			 */
			ath_hal_setcapability(sc->sc_ah, HAL_CAP_DIVERSITY, 
					      HAL_CAP_STRONG_DIV, dfs->dfs_rinfo.rn_fastdivGCval, NULL);
			rfilt |= HAL_RX_FILTER_PHYRADAR;
			ath_hal_setrxfilter(sc->sc_ah, rfilt);
		}
	} else {
		DFS_DPRINTK(sc, ATH_DEBUG_DFS, "%s: Disabling AR\n", __func__);
		rfilt = ath_hal_getrxfilter(sc->sc_ah);
		rfilt &= ~HAL_RX_FILTER_PHYRADAR;
		ath_hal_setrxfilter(sc->sc_ah,rfilt);
		/* Enable strong signal fast antenna diversity */
		ath_hal_setcapability(sc->sc_ah, HAL_CAP_DIVERSITY, 
				      HAL_CAP_STRONG_DIV, dfs->dfs_rinfo.rn_fastdivGCval, NULL);

	}
#endif    
}


/*
 * Disable AR if AR channel
 */

void ath_ar_disable(struct ath_dfs *dfs)
{
#if 0
	u_int32_t rfilt;
	struct ieee80211_channel *chan=&sc->sc_curchan;
	struct ath_dfs *dfs=ic->ic_dfs;
	if (dfs == NULL) {
		DFS_DPRINTK(sc, ATH_DEBUG_DFS, "%s: sc_dfs is NULL\n",
			__func__);
		return;
	}
	if ((chan->channel_flags & CHANNEL_108G) == CHANNEL_108G) {
		/* Enable strong signal fast antenna diversity */
		ath_hal_setcapability(sc->sc_ah, HAL_CAP_DIVERSITY, 
				      HAL_CAP_STRONG_DIV, dfs->dfs_rinfo.rn_fastdivGCval, NULL);
		rfilt = ath_hal_getrxfilter(sc->sc_ah);
		rfilt &= ~HAL_RX_FILTER_PHYERR;
		ath_hal_setrxfilter(sc->sc_ah, rfilt);
		dfs_reset_ar(sc);
		dfs_reset_arq(sc);
	}
#endif    
}

void dfs_process_ar_event(struct ath_dfs *dfs, struct ieee80211_channel *chan)
{
	struct dfs_ar_state *ar;
	struct dfs_event *re=NULL;
	u_int32_t sumpeak=0,numpeaks,rssi,width,origregionsum=0, i;
	u_int16_t thistimestamp;
	int empty;

	if (dfs == NULL) {
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS1,
		    "%s: sc_dfs is NULL\n",
		    __func__);
		return;
	}
	ar = (struct dfs_ar_state *) &(dfs->dfs_ar_state);
	ATH_ARQ_LOCK(dfs);
	empty = STAILQ_EMPTY(&(dfs->dfs_arq));
	ATH_ARQ_UNLOCK(dfs);
	while (!empty) {
		ATH_ARQ_LOCK(dfs);
		re = STAILQ_FIRST(&(dfs->dfs_arq));
		if (re != NULL)
			STAILQ_REMOVE_HEAD(&(dfs->dfs_arq), re_list);
		ATH_ARQ_UNLOCK(dfs);
		if (re == NULL)
			return;

		thistimestamp = re->re_ts;
		rssi = re->re_rssi;
		width = re->re_dur;

		/* Return the dfs event to the free event list */
		OS_MEMZERO(re, sizeof(struct dfs_event));
		ATH_DFSEVENTQ_LOCK(dfs);
		STAILQ_INSERT_TAIL(&(dfs->dfs_eventq), re, re_list);
		ATH_DFSEVENTQ_UNLOCK(dfs);

		/* determine if current radar is an extension of previous radar */
		if (ar->ar_prevwidth == 255) {
			/* tag on previous width for consideraion of low data rate ACKs */
			ar->ar_prevwidth += width;
			width = (width == 255) ? 255 : ar->ar_prevwidth;
		} else if ((width == 255) &&
			   (ar->ar_prevwidth == 510 ||
			    ar->ar_prevwidth == 765 ||
			    ar->ar_prevwidth == 1020)) {
			/* Aggregate up to 5 consecuate max radar widths
			 * to consider 11Mbps long preamble 1500-byte pkts
			 */
			ar->ar_prevwidth += width;
		} else if (ar->ar_prevwidth == 1275 && width != 255) {
			/* Found 5th consecute maxed out radar, reset history */
			width += ar->ar_prevwidth;
			ar->ar_prevwidth = 0;
		} else if (ar->ar_prevwidth > 255) {
			/* Ignore if there are less than 5 consecutive maxed out radars */
			ar->ar_prevwidth = width;
			width = 255;
		} else {
			ar->ar_prevwidth = width;
		}
		/* For ignoring noises with radar duration in ranges of 3-30: AP4x */
		if ((width >= 257 && width <= 278) ||	/* Region 7 - 5.5Mbps (long pre) ACK = 270 = 216 us */
		    (width >= 295 && width <= 325) ||	/* Region 8 - 2Mbps (long pre) ACKC = 320 = 256us */
		    (width >= 1280 && width <= 1300)) {
			u_int16_t wraparoundadj=0;
			u_int16_t base = (width >= 1280) ? 1275 : 255;
			if (thistimestamp < ar->ar_prevtimestamp) {
				wraparoundadj = 32768;
			}
			if ((thistimestamp + wraparoundadj - ar->ar_prevtimestamp) !=
			    (width - base)) {
				width = 1;
			}
		}
		if (width <= 10) {
			ATH_ARQ_LOCK(dfs);
			empty = STAILQ_EMPTY(&(dfs->dfs_arq));
			ATH_ARQ_UNLOCK(dfs);
			continue;
		}
		/*
		 * Overloading the width=2 in: Store a count of radars w/max duration
		 * and high RSSI (not noise)
		 */
		if ((width == 255) && (rssi > DFS_AR_RSSI_THRESH_STRONG_PKTS))
			width = 2;
		/*
		 * Overloading the width=3 bin:
		 *   Double and store a count of rdars of durtaion that matches 11Mbps (long preamble)
		 *   TCP ACKs or 1500-byte data packets
		 */
		if ((width >= 1280 && width <= 1300) ||
		    (width >= 318 && width <= 325)) {
			width = 3;
			ar->ar_phyerrcount[3] += 2;
			ar->ar_acksum += 2;
		}
		/* build histogram of radar duration */
		if (width > 0 && width <= 510)
			ar->ar_phyerrcount[width]++;
		else {
			/* invalid radar width, throw it away */
			ATH_ARQ_LOCK(dfs);
			empty = STAILQ_EMPTY(&(dfs->dfs_arq));
			ATH_ARQ_UNLOCK(dfs);
			continue;
		}
		/* Received radar of interest (i.e., signature match), proceed to check if
		 * there is enough neighboring traffic to drop out of Turbo 
		 */
		if ((width >= 33 && width <= 38) ||          /* Region 0: 24Mbps ACK = 35 = 28us */
		    (width >= 39 && width <= 44) ||          /* Region 1: 12Mbps ACK = 40 = 32us */
		    (width >= 53 && width <= 58) ||          /* Region 2:  6Mbps ACK = 55 = 44us */
		    (width >= 126 && width <= 140) ||        /* Region 3: 11Mbps ACK = 135 = 108us */
		    (width >= 141 && width <= 160) ||        /* Region 4: 5.5Mbps ACK = 150 = 120us */
		    (width >= 189 && width <= 210) ||        /* Region 5:  2Mbps ACK = 200 = 160us */
		    (width >= 360 && width <= 380) ||        /* Region 6   1Mbps ACK = 400 = 320us */
		    (width >= 257 && width <= 270) ||        /* Region 7   5.5Mbps (Long Pre) ACK = 270 = 216us */
		    (width >= 295 && width <= 302) ||        /* Region 8   2Mbps (Long Pre) ACK = 320 = 256us */
		    /* Ignoring Region 9 due to overlap with 255 which is same as board noise */
		    /* Region 9  11Mbps (Long Pre) ACK = 255 = 204us */            
		    (width == 3)) {
			ar->ar_acksum++;
			/* double the count for strong radars that match one of the ACK signatures */
			if (rssi > DFS_AR_RSSI_DOUBLE_THRESHOLD) {
				ar->ar_phyerrcount[width]++;
				ar->ar_acksum++;
			}
			UPDATE_TOP_THREE_PEAKS(ar->ar_phyerrcount,
					       ar->ar_peaklist, width);
			/* sum the counts of these peaks */
			numpeaks = DFS_AR_MAX_NUM_PEAKS;
			origregionsum = ar->ar_acksum;
			for (i = 0; i < DFS_AR_MAX_NUM_PEAKS; i++) {
				if (ar->ar_peaklist[i] > 0) {
					if ((i==0) &&
					    (ar->ar_peaklist[i] == 3) &&
					    (ar->ar_phyerrcount[3] <
					     ar->ar_phyerrcount[2]) &&
					    (ar->ar_phyerrcount[3] > 6)) {
						/*
						 * If the top peak is one that
						 * maches the 11Mbps long
						 * preamble TCP Ack/1500-byte
						 * data, include the count for
						 * radars that hav emax
						 * duration and high rssi
						 * (width = 2) to boost the
						 * sum for the PAR test that
						 * follows */
						sumpeak += (ar->ar_phyerrcount[2]
							    + ar->ar_phyerrcount[3]);
						ar->ar_acksum += (ar->ar_phyerrcount[2]
								  + ar->ar_phyerrcount[3]);
					} else {
						sumpeak += ar->ar_phyerrcount[ar->ar_peaklist[i]];
					}
				} else 
					numpeaks--;
			}
			/*
			 * If sum of patterns matches exceeds packet threshold,
			 * perform comparison between peak-to-avg ratio against parThreshold
			 */
			if ((ar->ar_acksum > ar->ar_packetthreshold) &&
			    ((sumpeak * DFS_AR_REGION_WIDTH) > (ar->ar_parthreshold * numpeaks *
								ar->ar_acksum))) {
				/* neighboring traffic detected, get out of Turbo */
				chan->ic_flagext|= CHANNEL_INTERFERENCE;
				OS_MEMZERO(ar->ar_peaklist, sizeof(ar->ar_peaklist));
				ar->ar_acksum = 0;
				OS_MEMZERO(ar->ar_phyerrcount, sizeof(ar->ar_phyerrcount));
			} else {
				/*
				 * reset sum of matches to discount the count of
				 * strong radars with max duration
				 */
				ar->ar_acksum = origregionsum;
			}
		}
		ar->ar_prevtimestamp = thistimestamp;
		ATH_ARQ_LOCK(dfs);
		empty = STAILQ_EMPTY(&(dfs->dfs_arq));
		ATH_ARQ_UNLOCK(dfs);
	}
}

void dfs_reset_ar(struct ath_dfs *dfs)
{

	if (dfs == NULL) {
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS,
		    "%s: sc_dfs is NULL\n",
		    __func__);
		return;
	}
	OS_MEMZERO(&dfs->dfs_ar_state, sizeof(dfs->dfs_ar_state));
	dfs->dfs_ar_state.ar_packetthreshold = DFS_AR_PKT_COUNT_THRESH;
	dfs->dfs_ar_state.ar_parthreshold = DFS_AR_ACK_DETECT_PAR_THRESH;
}

void dfs_reset_arq(struct ath_dfs *dfs)
{
	struct dfs_event *event;

	if (dfs == NULL) {
		DFS_DPRINTK(dfs, ATH_DEBUG_DFS, "%s: sc_dfs is NULL\n",
			__func__);
		return;
	}
	ATH_ARQ_LOCK(dfs);
	ATH_DFSEVENTQ_LOCK(dfs);
	while (!STAILQ_EMPTY(&(dfs->dfs_arq))) {
		event = STAILQ_FIRST(&(dfs->dfs_arq));
		STAILQ_REMOVE_HEAD(&(dfs->dfs_arq), re_list);
		OS_MEMZERO(event, sizeof(struct dfs_event));
		STAILQ_INSERT_TAIL(&(dfs->dfs_eventq), event, re_list);
	}
	ATH_DFSEVENTQ_UNLOCK(dfs);
	ATH_ARQ_UNLOCK(dfs);
}


#endif /* ATH_SUPPORT_DFS */
