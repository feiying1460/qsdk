/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#ifndef _OL_RAWMODE_SIM_API__H_
#define _OL_RAWMODE_SIM_API__H_

#include <qdf_nbuf.h>           /* qdf_nbuf_t */
#include <ieee80211_var.h>      /* Generally required constructs */
#include <cdp_txrx_cmn.h>        /* ol_txrx_vdev_t, etc*/


/* Raw Mode simulation - conversion between Raw 802.11 format and other
 * formats.
 */

/* Statistics for the Raw Mode simulation module. These do not cover events
 * occurring outside the modules (such as higher layer failures to process a
 * successfully decapped MPDU, etc.)*/

struct ol_txrx_rawmode_pkt_sim_rxstats {
    /* Rx Side simulation module statistics */

    /* Decap successes */

    /* Number of non-AMSDU bearing MPDUs decapped */
    u_int64_t num_rx_mpdu_noamsdu;

    /* Number of A-MSDU bearing MPDUs (fitting within single nbuf)
       decapped */
    u_int64_t num_rx_smallmpdu_withamsdu;

    /* Number of A-MSDU bearing MPDUs (requiring multiple nbufs) decapped */
    u_int64_t num_rx_largempdu_withamsdu;


    /* Decap errors */

    /* Number of MSDUs (contained in A-MSDU) with invalid length field */
    u_int64_t num_rx_inval_len_msdu;

    /* Number of A-MSDU bearing MPDUs which are shorter than expected from
       parsing A-MSDU fields */
    u_int64_t num_rx_tooshort_mpdu;

    /* Number of A-MSDU bearing MPDUs received which are longer than
       expected from parsing A-MSDU fields */
    u_int64_t num_rx_toolong_mpdu;

    /* Number of non-AMSDU bearing MPDUs (requiring multiple nbufs) seen
       (unhandled) */
    u_int64_t num_rx_chainedmpdu_noamsdu;

    /* Add anything else of interest */
};

struct ol_txrx_rawmode_pkt_sim_txstats {
    /* Tx Side simulation module statistics */

    /* Number of non-AMSDU bearing MPDUs encapped */
    u_int64_t num_tx_mpdu_noamsdu;

    /* Number of A-MSDU bearing MPDUs encapped */
    u_int64_t num_tx_mpdu_withamsdu;

    /* Add anything else of interest */
};

/**
 * @brief decap a list of nbufs from 802.11 Raw format to Ethernet II format
 * @details
 *  Note that the list head can be set to NULL if errors are encountered
 *  for each and every nbuf in the list.
 *
 * @param vdev - the data virtual device object
 * @param peer - the peer object
 * @param pdeliver_list_head - pointer to head of delivery list
 * @param pdeliver_list_head - pointer to tail of delivery list
 */
extern void
ol_rsim_rx_decap(struct ol_txrx_vdev_t *vdev,
        struct ol_txrx_peer_t *peer,
        qdf_nbuf_t *pdeliver_list_head,
        qdf_nbuf_t *pdeliver_list_tail);


/**
 * @brief print raw mode packet simulation statistics
 *
 * @param vdev - the data virtual device object
 */
extern void
ol_txrx_print_rawmode_pkt_sim_stats(ol_txrx_vdev_handle vdev);

/**
 * @brief clear raw mode packet simulation statistics
 *
 * @param vdev - the data virtual device object
 */
extern void
ol_txrx_clear_rawmode_pkt_sim_stats(ol_txrx_vdev_handle vdev);

#endif /* _OL_RAWMODE_SIM_API__H_ */
