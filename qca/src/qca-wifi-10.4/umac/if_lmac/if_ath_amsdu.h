/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */
#ifndef _ATH_AMSDU_H_
#define _ATH_AMSDU_H_

/*
 * AMSDU Frame
 */
#define	ATH_AMSDU_TXQ_LOCK_INIT(_scn)    spin_lock_init(&(_scn)->amsdu_txq_lock)
#define	ATH_AMSDU_TXQ_LOCK_DESTROY(_scn)
#define	ATH_AMSDU_TXQ_LOCK(_scn)     spin_lock(&(_scn)->amsdu_txq_lock)
#define	ATH_AMSDU_TXQ_UNLOCK(_scn)   spin_unlock(&(_scn)->amsdu_txq_lock)

/*
 * External Definitions
 */
struct ath_amsdu_tx {
    wbuf_t                  amsdu_tx_buf; /* amsdu staging area */
    TAILQ_ENTRY(ath_amsdu_tx) amsdu_qelem; /* round-robin amsdu tx entry */
    u_int                   sched;
};

struct ath_amsdu {
    struct ath_amsdu_tx     amsdutx[WME_NUM_TID];
};

int  ath_amsdu_attach(struct ath_softc_net80211 *scn);
void ath_amsdu_detach(struct ath_softc_net80211 *scn);
int  ath_amsdu_node_attach(struct ath_softc_net80211 *scn, struct ath_node_net80211 *anode);
void ath_amsdu_node_detach(struct ath_softc_net80211 *scn, struct ath_node_net80211 *anode);
wbuf_t ath_amsdu_send(wbuf_t wbuf);
void ath_amsdu_complete_wbuf(wbuf_t wbuf);
void ath_amsdu_tx_drain(struct ath_softc_net80211 *scn);

#endif /* _ATH_AMSDU_H_ */
