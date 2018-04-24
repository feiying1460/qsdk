/*
* Copyright (c) 2013,2015 Qualcomm Atheros, Inc..
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

struct meta_hdr_s {
    uint8_t magic;
    uint8_t flags;
    uint8_t channel;
    uint8_t keyix;

    uint8_t rssi;
    uint8_t silence;
    uint8_t power;
    uint8_t retries;

    uint8_t max_tries[2];
    uint8_t rates[2];

    uint8_t unused[4];
};

struct tx_capture_hdr {
    uint8_t    ta[IEEE80211_ADDR_LEN]; /* transmitter mac address */
    uint8_t    ra[IEEE80211_ADDR_LEN]; /* receiver mac address */
    uint16_t   ppdu_id; /* ppdu_id */
};

#define METAHDR_FLAG_TX                 (1<<0) /* packet transmission */
#define METAHDR_FLAG_TX_FAIL            (1<<1) /* transmission failed */
#define METAHDR_FLAG_TX_USED_ALT_RATE   (1<<2) /* used alternate bitrate */
#define METAHDR_FLAG_AUTO_RATE          (1<<5)
#define METAHDR_FLAG_NOENCRYPT          (1<<6)
#define METAHDR_FLAG_NOQOS              (1<<7)

#define METAHDR_FLAG_RX_ERR             (1<<3) /* failed crc check */
#define METAHDR_FLAG_RX_MORE            (1<<4) /* first part of a fragmented skb */
#define METAHDR_FLAG_LOG                (1<<7)

#define METAHDR_FLAG_RX_4SS             (1<<1) /* rx 4ss frame */
