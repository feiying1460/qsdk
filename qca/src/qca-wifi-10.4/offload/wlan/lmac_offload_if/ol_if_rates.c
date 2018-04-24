/*
 * Copyright (c) 2011, Atheros Communications Inc.
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
 * LMAC offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "sw_version.h"
#include "targaddrs.h"
#include "ol_helper.h"

#if ATH_PERF_PWR_OFFLOAD

typedef struct _ol_ath_rate_table {
    u_int32_t num_rates;
    struct {
        u_int8_t    valid;      /* valid for rate control use */
        u_int8_t    phy;        /* IEEE80211_T_DS/IEEE80211_T_OFDM/XR */
        u_int8_t    dot11_rate; /* value for supported rates. info element of MLME */
    } info[IEEE80211_RATE_MAXSIZE];
} ol_ath_rate_table;

ol_ath_rate_table ol_if_11a_table = {
	8,  /* number of rates */
	{
/*--- IEEE80211_T_OFDM rates ---*/
/*   6 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|12)},
/*   9 Mb */ {  TRUE, IEEE80211_T_OFDM,  18       },
/*  12 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|24)},
/*  18 Mb */ {  TRUE, IEEE80211_T_OFDM,  36       },
/*  24 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|48)},
/*  36 Mb */ {  TRUE, IEEE80211_T_OFDM,  72       },
/*  48 Mb */ {  TRUE, IEEE80211_T_OFDM,  96       },
/*  54 Mb */ {  TRUE, IEEE80211_T_OFDM,  108      }
	},
};

ol_ath_rate_table ol_if_11a_halfrate_table = {
	8,  /* number of rates */
	{
/*--- IEEE80211_T_OFDM rates ---*/
/*   6 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|6)},
/*   9 Mb */ {  TRUE, IEEE80211_T_OFDM,  9       },
/*  12 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|12)},
/*  18 Mb */ {  TRUE, IEEE80211_T_OFDM,  18       },
/*  24 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|24)},
/*  36 Mb */ {  TRUE, IEEE80211_T_OFDM,  36       },
/*  48 Mb */ {  TRUE, IEEE80211_T_OFDM,  48       },
/*  54 Mb */ {  TRUE, IEEE80211_T_OFDM,  54      }
	},
};

ol_ath_rate_table ol_if_11a_quarterrate_table = {
	8,  /* number of rates */
	{
/*--- IEEE80211_T_OFDM rates ---*/
/*   6 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|3)},
/*   9 Mb */ {  TRUE, IEEE80211_T_OFDM,  4       },
/*  12 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|6)},
/*  18 Mb */ {  TRUE, IEEE80211_T_OFDM,  9       },
/*  24 Mb */ {  TRUE, IEEE80211_T_OFDM,  (0x80|12)},
/*  36 Mb */ {  TRUE, IEEE80211_T_OFDM,  18       },
/*  48 Mb */ {  TRUE, IEEE80211_T_OFDM,  24       },
/*  54 Mb */ {  TRUE, IEEE80211_T_OFDM,  27      }
	},
};

ol_ath_rate_table ol_if_11b_table = {
	4,  /* number of rates */
	{
/*   1 Mb */ {  TRUE,  IEEE80211_T_DS,  (0x80| 2)},
/*   2 Mb */ {  TRUE,  IEEE80211_T_DS,  (0x80| 4)},
/* 5.5 Mb */ {  TRUE,  IEEE80211_T_DS,  (0x80|11)},
/*  11 Mb */ {  TRUE,  IEEE80211_T_DS,  (0x80|22)}
	},
};


ol_ath_rate_table ol_if_11g_table = {
	12,  /* number of rates */
	{
/*   1 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80| 2)},
/*   2 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80| 4)},
/* 5.5 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80|11)},
/*  11 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80|22)},
/* Hardware workaround - remove rates 6, 9 from rate ctrl */
/*--- IEEE80211_T_OFDM rates ---*/
/*   6 Mb */ { FALSE, IEEE80211_T_OFDM,  12},
/*   9 Mb */ { FALSE, IEEE80211_T_OFDM,  18},
/*  12 Mb */ {  TRUE, IEEE80211_T_OFDM,  24},
/*  18 Mb */ {  TRUE, IEEE80211_T_OFDM,  36},
/*  24 Mb */ {  TRUE, IEEE80211_T_OFDM,  48},
/*  36 Mb */ {  TRUE, IEEE80211_T_OFDM,  72},
/*  48 Mb */ {  TRUE, IEEE80211_T_OFDM,  96},
/*  54 Mb */ {  TRUE, IEEE80211_T_OFDM,  108}
	},
};


ol_ath_rate_table ol_if_11ng_table = {

    44,  /* number of rates */
	{
/*   1 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80| 2)},
/*   2 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80| 4)},
/* 5.5 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80|11)},
/*  11 Mb */ {  TRUE, IEEE80211_T_DS,   (0x80|22)},
/* Hardware workaround - remove rates 6, 9 from rate ctrl */
/*--- IEEE80211_T_OFDM rates ---*/
/*   6 Mb */ { FALSE, IEEE80211_T_OFDM,  12},
/*   9 Mb */ { FALSE, IEEE80211_T_OFDM,  18},
/*  12 Mb */ {  TRUE, IEEE80211_T_OFDM,  24},
/*  18 Mb */ {  TRUE, IEEE80211_T_OFDM,  36},
/*  24 Mb */ {  TRUE, IEEE80211_T_OFDM,  48},
/*  36 Mb */ {  TRUE, IEEE80211_T_OFDM,  72},
/*  48 Mb */ {  TRUE, IEEE80211_T_OFDM,  96},
/*  54 Mb */ {  TRUE, IEEE80211_T_OFDM,  108},
/*--- IEEE80211_T_HT SS rates ---*/
/* 6.5 Mb */ {  TRUE, IEEE80211_T_HT,   0},
/*  13 Mb */ {  TRUE, IEEE80211_T_HT,  	1},
/*19.5 Mb */ {  TRUE, IEEE80211_T_HT,   2},
/*  26 Mb */ {  TRUE, IEEE80211_T_HT,  	3},
/*  39 Mb */ {  TRUE, IEEE80211_T_HT,  	4},
/*  52 Mb */ {  TRUE, IEEE80211_T_HT, 	5},
/*58.5 Mb */ {  TRUE, IEEE80211_T_HT,  	6},
/*  65 Mb */ {  TRUE, IEEE80211_T_HT,  	7},
/*--- IEEE80211_T_HT DS rates ---*/
/*  13 Mb */ {  TRUE, IEEE80211_T_HT,  	8},
/*  26 Mb */ {  TRUE, IEEE80211_T_HT,  	9},
/*  39 Mb */ {  TRUE, IEEE80211_T_HT,  	10},
/*  52 Mb */ {  TRUE, IEEE80211_T_HT,  	11},
/*  78 Mb */ {  TRUE, IEEE80211_T_HT,  	12},
/* 104 Mb */ {  TRUE, IEEE80211_T_HT,   13},
/* 117 Mb */ {  TRUE, IEEE80211_T_HT,   14},
/* 130 Mb */ {  TRUE, IEEE80211_T_HT,   15},
/*--- IEEE80211_T_HT TS rates ---*/
/*19.5 Mb */ {  TRUE, IEEE80211_T_HT,   16},
/* 39  Mb */ {  TRUE, IEEE80211_T_HT,   17},
/*58.5 Mb */ {  TRUE, IEEE80211_T_HT,   18},
/* 78  Mb */ {  TRUE, IEEE80211_T_HT,   19},
/*117  Mb */ {  TRUE, IEEE80211_T_HT,   20},
/*156  Mb */ {  TRUE, IEEE80211_T_HT,   21},
/*175.5Mb */ {  TRUE, IEEE80211_T_HT,   22},
/*195  Mb */ {  TRUE, IEEE80211_T_HT,   23},
/*--- IEEE80211_T_HT FS rates ---*/
/*19.5 Mb */ {  TRUE, IEEE80211_T_HT,   24},
/* 39  Mb */ {  TRUE, IEEE80211_T_HT,   25},
/*58.5 Mb */ {  TRUE, IEEE80211_T_HT,   26},
/* 78  Mb */ {  TRUE, IEEE80211_T_HT,   27},
/*117  Mb */ {  TRUE, IEEE80211_T_HT,   28},
/*156  Mb */ {  TRUE, IEEE80211_T_HT,   29},
/*175.5Mb */ {  TRUE, IEEE80211_T_HT,   30},
/*195  Mb */ {  TRUE, IEEE80211_T_HT,   31},
	},
};

static ol_ath_rate_table ol_if_11na_table = {

    40,  /* number of rates */
	{
/*--- IEEE80211_T_OFDM rates ---*/
/*   6 Mb */ {  TRUE, IEEE80211_T_OFDM,(0x80|12)},
/*   9 Mb */ {  TRUE, IEEE80211_T_OFDM,18       },
/*  12 Mb */ {  TRUE, IEEE80211_T_OFDM,(0x80|24)},
/*  18 Mb */ {  TRUE, IEEE80211_T_OFDM,36       },
/*  24 Mb */ {  TRUE, IEEE80211_T_OFDM,(0x80|48)},
/*  36 Mb */ {  TRUE, IEEE80211_T_OFDM,72       },
/*  48 Mb */ {  TRUE, IEEE80211_T_OFDM,96       },
/*  54 Mb */ {  TRUE, IEEE80211_T_OFDM,108      },
/*--- IEEE80211_T_HT SS rates ---*/
/* 6.5 Mb */ {  TRUE, IEEE80211_T_HT,  0},
/*  13 Mb */ {  TRUE, IEEE80211_T_HT,  1},
/*19.5 Mb */ {  TRUE, IEEE80211_T_HT,  2},
/*  26 Mb */ {  TRUE, IEEE80211_T_HT,  3},
/*  39 Mb */ {  TRUE, IEEE80211_T_HT,  4},
/*  52 Mb */ {  TRUE, IEEE80211_T_HT,  5},
/*58.5 Mb */ {  TRUE, IEEE80211_T_HT,  6},
/*  65 Mb */ {  TRUE, IEEE80211_T_HT,  7},
/*--- IEEE80211_T_HT DS rates ---*/
/*  13 Mb */ {  TRUE, IEEE80211_T_HT,  8},
/*  26 Mb */ {  TRUE, IEEE80211_T_HT,  9},
/*  39 Mb */ {  TRUE, IEEE80211_T_HT, 10},
/*  52 Mb */ {  TRUE, IEEE80211_T_HT, 11},
/*  78 Mb */ {  TRUE, IEEE80211_T_HT, 12},
/* 104 Mb */ {  TRUE, IEEE80211_T_HT, 13},
/* 117 Mb */ {  TRUE, IEEE80211_T_HT, 14},
/* 130 Mb */ {  TRUE, IEEE80211_T_HT, 15},
/*--- IEEE80211_T_HT TS rates ---*/
/*19.5 Mb */ {  TRUE, IEEE80211_T_HT, 16},
/* 39  Mb */ {  TRUE, IEEE80211_T_HT, 17},
/*58.5 Mb */ {  TRUE, IEEE80211_T_HT, 18},
/* 78  Mb */ {  TRUE, IEEE80211_T_HT, 19},
/*117  Mb */ {  TRUE, IEEE80211_T_HT, 20},
/*156  Mb */ {  TRUE, IEEE80211_T_HT, 21},
/*175.5Mb */ {  TRUE, IEEE80211_T_HT, 22},
/*195  Mb */ {  TRUE, IEEE80211_T_HT, 23},
/*--- IEEE80211_T_HT FS rates ---*/
/*19.5 Mb */ {  TRUE, IEEE80211_T_HT, 24},
/* 39  Mb */ {  TRUE, IEEE80211_T_HT, 25},
/*58.5 Mb */ {  TRUE, IEEE80211_T_HT, 26},
/* 78  Mb */ {  TRUE, IEEE80211_T_HT, 27},
/*117  Mb */ {  TRUE, IEEE80211_T_HT, 28},
/*156  Mb */ {  TRUE, IEEE80211_T_HT, 29},
/*175.5Mb */ {  TRUE, IEEE80211_T_HT, 30},
/*195  Mb */ {  TRUE, IEEE80211_T_HT, 31},
	},
};


typedef enum _ol_ath_rate_type {
    OL_ATH_NORMAL_RATE,
   OL_ATH_HALF_RATE,
   OL_ATH_QUARTER_RATE
} ol_ath_rate_type;


static void
ol_ath_rate_setup(struct ieee80211com *ic, enum ieee80211_phymode mode,
                  ol_ath_rate_type type, const ol_ath_rate_table *rt)
{
    struct ieee80211_rateset *rs;
    int i, maxrates, rix;

    if (mode >= IEEE80211_MODE_MAX) {
        return;
    }

    if (rt->num_rates > IEEE80211_RATE_MAXSIZE) {
        maxrates = IEEE80211_RATE_MAXSIZE;
    } else {
        maxrates = rt->num_rates;
    }

    switch (type) {
    case OL_ATH_NORMAL_RATE:
        rs = IEEE80211_SUPPORTED_RATES(ic, mode);
        break;
    case OL_ATH_HALF_RATE:
        rs = IEEE80211_HALF_RATES(ic);
        break;
    case OL_ATH_QUARTER_RATE:
        rs = IEEE80211_QUARTER_RATES(ic);
        break;
    default:
        return;
    }

    /* supported rates (non IEEE80211_T_HT) */
    rix = 0;
    for (i = 0; i < maxrates; i++) {
        if ((rt->info[i].phy == IEEE80211_T_HT))
            continue;
        rs->rs_rates[rix++] = rt->info[i].dot11_rate;
    }
    rs->rs_nrates = (u_int8_t)rix;
    if ((mode == IEEE80211_MODE_11NA_HT20)     || (mode == IEEE80211_MODE_11NG_HT20)      ||
        (mode == IEEE80211_MODE_11NA_HT40PLUS) || (mode == IEEE80211_MODE_11NA_HT40MINUS) ||
        (mode == IEEE80211_MODE_11NG_HT40PLUS) || (mode == IEEE80211_MODE_11NG_HT40MINUS) ||
        (mode == IEEE80211_MODE_11AC_VHT20) || (mode == IEEE80211_MODE_11AC_VHT40PLUS) ||
        (mode == IEEE80211_MODE_11AC_VHT40MINUS) || (mode == IEEE80211_MODE_11AC_VHT80) ||
        (mode == IEEE80211_MODE_11AC_VHT160) || (mode == IEEE80211_MODE_11AC_VHT80_80)) {
        /* supported rates (HT) */
        rix = 0;
        rs = IEEE80211_HT_RATES(ic, mode);
        for (i = 0; i < maxrates; i++) {
            if (rt->info[i].phy == IEEE80211_T_HT) {
                rs->rs_rates[rix++] = rt->info[i].dot11_rate;
            }
        }
        rs->rs_nrates = (u_int8_t)rix;
    }
}

void
ol_ath_vht_rate_setup(struct ieee80211com *ic, u_int16_t mcs_map,
                      u_int16_t max_datarate, u_int16_t basic_mcs)
{
    /* Set the VHT Supported MCS subset and highest data rate*/
    ieee80211com_set_vht_high_data_rate(ic, max_datarate);
    ieee80211com_set_vht_mcs_map( ic, mcs_map);

    /* Set up the VHT Basic MCS rate set. Use only the relevant 16 bits */
    ieee80211com_set_vhtop_basic_mcs_map(ic, basic_mcs);
}

void ol_ath_setup_rates(struct ieee80211com *ic)
{
    ol_ath_rate_setup(ic, IEEE80211_MODE_11A, OL_ATH_NORMAL_RATE, &ol_if_11a_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11A, OL_ATH_HALF_RATE, &ol_if_11a_halfrate_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11A, OL_ATH_QUARTER_RATE, &ol_if_11a_quarterrate_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11G, OL_ATH_NORMAL_RATE, &ol_if_11g_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11B, OL_ATH_NORMAL_RATE, &ol_if_11b_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NA_HT20, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NA_HT40PLUS, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NA_HT40MINUS, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NA_HT40, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NG_HT20, OL_ATH_NORMAL_RATE, &ol_if_11ng_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NG_HT40PLUS, OL_ATH_NORMAL_RATE, &ol_if_11ng_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NG_HT40MINUS, OL_ATH_NORMAL_RATE, &ol_if_11ng_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11NG_HT40, OL_ATH_NORMAL_RATE, &ol_if_11ng_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT20, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT40PLUS, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT40MINUS, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT40, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT80, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT160, OL_ATH_NORMAL_RATE, &ol_if_11na_table );
    ol_ath_rate_setup(ic, IEEE80211_MODE_11AC_VHT80_80, OL_ATH_NORMAL_RATE, &ol_if_11na_table );

    /* TO-DO: quarter and half rates */
}

#endif
