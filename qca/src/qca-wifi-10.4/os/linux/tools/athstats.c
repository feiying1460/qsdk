/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc
 */

/* Copyright (c) 2010, Atheros Communications Inc.
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
 * Simple Atheros-specific tool to inspect and monitor network traffic
 * statistics.
 *  athstats [-i interface]
 * (default interface is wifi0).  If interval is specified a rolling output
 * is displayed every interval seconds.
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <err.h>
#include <unistd.h>
#include <ctype.h>

#include "ah_desc.h"
#include "if_athioctl.h"

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN 1234  /* LSB first: i386, vax */
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321/* MSB first: 68000, ibm, net */
#endif
#ifndef ATH_SUPPORT_LINUX_STA
#include <asm/byteorder.h>
#endif
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

/*
 * ol_params.h has types defined for the kernel space
 * athtypes_linux.h has definitions for kernel space
 * data types
 */
#if ATH_PERF_PWR_OFFLOAD
#include "athtypes_linux.h"
#include "cdp_txrx_stats_struct.h"
#endif

#include "os/linux/include/ieee80211_external.h"


#define IS_RSSI_VALID(_rssi) ((_rssi) && (_rssi != -0x80))

struct phy_radiolevel_stats {
    u_int64_t rx_phyerr;
    u_int64_t rx_crcerr;
    u_int64_t rx_decrypterr;
    u_int64_t rx_demicerr;
    u_int64_t rx_fifoerr;
    u_int64_t rx_decrypt_busyerr;
} radiostats;
static const struct {
    u_int       phyerr;
    const char* desc;
} phyerrdescriptions[] = {
    {HAL_PHYERR_UNDERRUN              ,  "phy tx underrun"          },
    {HAL_PHYERR_TIMING                ,  "phy timing error"         },
    {HAL_PHYERR_PARITY                ,  "Illegal Parity"           },
    {HAL_PHYERR_RATE                  ,  "Illegal Rate"             },
    {HAL_PHYERR_LENGTH                ,  "Illegal Length"           },
    {HAL_PHYERR_RADAR                 ,  "Radar detect"             },
    {HAL_PHYERR_SERVICE               ,  "Illegal service"          },
    {HAL_PHYERR_TOR                   ,  "Transmit override receive"},
    {HAL_PHYERR_OFDM_TIMING           ,  "phy ofdm timing"          },
    {HAL_PHYERR_OFDM_SIGNAL_PARITY    ,  "phy ofdm signal parity"   },
    {HAL_PHYERR_OFDM_RATE_ILLEGAL     ,  "phy ofdm rate illegal"    },
    {HAL_PHYERR_OFDM_LENGTH_ILLEGAL   ,  "phy ofdm length illegal"  },
    {HAL_PHYERR_OFDM_POWER_DROP       ,  "phy ofdm power drop"      },
    {HAL_PHYERR_OFDM_SERVICE          ,  "phy ofdm service"         },
    {HAL_PHYERR_OFDM_RESTART          ,  "phy ofdm restart"         },
    {HAL_PHYERR_CCK_TIMING            ,  "phy cck timing"           },
    {HAL_PHYERR_CCK_HEADER_CRC        ,  "phy cck header crc"       },
    {HAL_PHYERR_CCK_RATE_ILLEGAL      ,  "phy cck rate illegal"     },
    {HAL_PHYERR_CCK_SERVICE           ,  "phy cck service"          },
    {HAL_PHYERR_CCK_RESTART           ,  "phy cck restart"          },
    {HAL_PHYERR_CCK_LENGTH_ILLEGAL    ,  "phy cck length illegal"   },
    {HAL_PHYERR_CCK_POWER_DROP        ,  "phy cck power drop"       },
    {HAL_PHYERR_HT_CRC_ERROR          ,  "phy ht crc error"         },
    {HAL_PHYERR_HT_LENGTH_ILLEGAL     ,  "phy ht length illegal"    },
    {HAL_PHYERR_HT_RATE_ILLEGAL       ,  "phy ht rate illegal"      },
};

static char *qdesc[10] = { "BK","BE","VI","VO","","","","UAPSD","CAB","BEACON"};


static void
printphy_stats_curmode(FILE *fd, const struct ath_phy_stats *phy_stats)
{
/*CURRENT PHY STATS*/
    fprintf(fd, "CUR PHY stats:\n");
    fprintf(fd, "received phy error packets = %lld\n",
                                                   phy_stats->ast_rx_phyerr);
    fprintf(fd, "received crc error packets = %lld\n",
                                                    phy_stats->ast_rx_crcerr);
    fprintf(fd, "received decrypt error packets = %lld\n",
                                                 phy_stats->ast_rx_decrypterr);
    fprintf(fd, "received demic error packets = %lld\n",
                                                  phy_stats->ast_rx_demicerr);
    fprintf(fd, "received fifo error packets = %lld\n",
                                                   phy_stats->ast_rx_fifoerr);
    fprintf(fd, "received decrypt busy error packets = %lld\n",
                                            phy_stats->ast_rx_decrypt_busyerr);
}
static void
printphy_stats(FILE *fd, const struct phy_radiolevel_stats *phy_stats)
{

/*PHY STATS*/

    fprintf(fd, "PHY stats:\n");
    fprintf(fd, "received phy error packets = %lld\n",phy_stats->rx_phyerr);
    fprintf(fd, "received crc error packets = %lld\n",phy_stats->rx_crcerr);
    fprintf(fd, "received decrypt error packets = %lld\n",
                                                 phy_stats->rx_decrypterr);
    fprintf(fd, "received demic error packets = %lld\n",
                                                    phy_stats->rx_demicerr);
    fprintf(fd, "received fifo error packets = %lld\n",phy_stats->rx_fifoerr);
    fprintf(fd, "received decrypt busy error packets = %lld\n",
                                           phy_stats->rx_decrypt_busyerr);
}

static void
print_mib_stats(FILE *fd, const struct ath_stats *stats)
{
    fprintf(fd, "MIB stats:\n");
    if (stats->ast_mib_stats.ast_ackrcv_bad)
        fprintf(fd, "%u Bad Ack received\n", stats->ast_mib_stats.ast_ackrcv_bad);
    if (stats->ast_mib_stats.ast_rts_bad)
        fprintf(fd, "%u Bad RTS\n", stats->ast_mib_stats.ast_rts_bad);
    if (stats->ast_mib_stats.ast_rts_good)
        fprintf(fd, "%u Good RTS\n", stats->ast_mib_stats.ast_rts_good);
    if (stats->ast_mib_stats.ast_fcs_bad)
        fprintf(fd, "%u Bad FCS\n", stats->ast_mib_stats.ast_fcs_bad);
    if (stats->ast_mib_stats.ast_beacons)
        fprintf(fd, "%u Beacons\n", stats->ast_mib_stats.ast_beacons);
}

static void
printstats(FILE *fd, const struct ath_stats *stats)
{
#define N(a)    (sizeof(a) / sizeof(a[0]))

#define STAT(x,fmt) \
    if (stats->ast_##x) fprintf(fd, "%10u " fmt "\n", (unsigned int)stats->ast_##x)
#define STAT64(x,fmt) \
    if (stats->ast_##x) fprintf(fd, "%llu " fmt "\n", \
	(long long unsigned int) stats->ast_##x)
#define STAT_PEEK_11N(_x)   stats->ast_11n_stats._x
#define STAT_11N(x, descr) \
    fprintf(fd, "%10u " descr "\n", STAT_PEEK_11N(x))
#define STAT_11N_P(x, y, descr) \
    fprintf(fd, "%10.2f " descr "\n", \
            100*(float)STAT_PEEK_11N(x)/((float)(STAT_PEEK_11N(y))+1))
#define STAT_FMT(x,fmt) \
    if (stats->ast_##x) fprintf(fd, "%10u " fmt "\n", stats->ast_##x)

    int i, j;

    STAT(watchdog, "watchdog timeouts");
    STAT(hardware, "hardware error interrupts");
    STAT(halresets, "HAL resets");
    STAT(bmiss, "beacon miss interrupts");
    STAT(rxorn, "recv overrun interrupts");
    STAT(rxeol, "recv eol interrupts");
    STAT(rxeol_recover, "recv eol interrupt recoveries");
    STAT(txurn, "txmit underrun interrupts");
    STAT(txto,  "global txmit timeout interrupts");
    STAT(cst,  "carrier sense timeout interrupts");
    STAT(mib,  "# mib interrupts");
    STAT(tx_packets, "# packets sent on the interface");
    STAT(rx_packets, "# packets receive on the interface");
    STAT(tx_mgmt, "tx management frames");

    STAT(tx_discard, "tx frames discarded prior to association");
    STAT(tx_invalid, "tx frames discarded 'cuz device gone");
    STAT(tx_qstop, "tx queue stopped because full");
    STAT(tx_encap, "tx encapsulation failed");
    STAT(tx_nonode, "tx failed 'cuz no node");
    STAT(tx_nobuf, "tx failed 'cuz no tx buffer (data)");
    STAT(tx_stop, "Number of times netif_stop called");
    STAT(tx_resume, "Number of times netif_wake called");
    STAT(tx_nobufmgt, "tx failed 'cuz no tx buffer (mgt)");
    STAT(tx_xretries, "tx failed 'cuz too many retries");
    STAT(tx_fifoerr, "tx failed 'cuz FIFO underrun");
    STAT(tx_filtered, "tx failed 'cuz xmit filtered");
    STAT(tx_badrate, "tx failed 'cuz bogus xmit rate");
    STAT(tx_noack, "tx frames with no ack marked");


    STAT(tx_cts, "tx frames with cts enabled");
    STAT(tx_shortpre, "tx frames with short preamble");
    STAT(tx_altrate, "tx frames with an alternate rate");
    STAT(tx_protect, "tx frames with 11g protection");
    STAT(rx_orn, "rx failed 'cuz of desc overrun");
    STAT(rx_badcrypt, "rx failed 'cuz decryption");
    STAT(rx_badmic, "rx failed 'cuz MIC failure");
    STAT(rx_nobuf, "rx setup failed 'cuz no skbuff");

	STAT(tx_rssi, "tx rssi of last ack");
    STAT64(rx_bytes, "total number of bytes received");
    STAT64(tx_bytes, "total number of bytes transmitted");


/* PHY statistics */

    if (IS_RSSI_VALID(stats->ast_tx_rssi_ctl0))
        fprintf(fd, "rssi of last ack[ctl, ch0]: %u\n",
                stats->ast_tx_rssi_ctl0);

    if (IS_RSSI_VALID(stats->ast_tx_rssi_ctl1))
        fprintf(fd, "rssi of last ack[ctl, ch1]: %u\n",
                stats->ast_tx_rssi_ctl1);

    if (IS_RSSI_VALID(stats->ast_tx_rssi_ctl2))
        fprintf(fd, "rssi of last ack[ctl, ch2]: %u\n",
                stats->ast_tx_rssi_ctl2);
    if (IS_RSSI_VALID(stats->ast_tx_rssi_ext0))
        fprintf(fd, "rssi of last ack[ext, ch0]: %u\n",
                stats->ast_tx_rssi_ext0);
    if (IS_RSSI_VALID(stats->ast_tx_rssi_ext1))
        fprintf(fd, "rssi of last ack[ext, ch1]: %u\n",
                stats->ast_tx_rssi_ext1);
    if (IS_RSSI_VALID(stats->ast_tx_rssi_ext2))
        fprintf(fd, "rssi of last ack[ext, ch2]: %u\n",
                stats->ast_tx_rssi_ext2);


    STAT(rx_rssi, "rx rssi from histogram [combined]");

    if (IS_RSSI_VALID(stats->ast_rx_rssi_ctl0))
        fprintf(fd, "rssi of last rcv[ctl, ch0]: %u\n",
                stats->ast_rx_rssi_ctl0);

    if (IS_RSSI_VALID(stats->ast_rx_rssi_ctl1))
        fprintf(fd, "rssi of last rcv[ctl, ch1]: %u\n",
                stats->ast_rx_rssi_ctl1);

    if (IS_RSSI_VALID(stats->ast_rx_rssi_ctl2))
        fprintf(fd, "rssi of last rcv[ctl, ch2]: %u\n",
                stats->ast_rx_rssi_ctl2);

    if (IS_RSSI_VALID(stats->ast_rx_rssi_ext0))
        fprintf(fd, "rssi of last rcv[ext, ch0]: %u\n",
                stats->ast_rx_rssi_ext0);

    if (IS_RSSI_VALID(stats->ast_rx_rssi_ext1))
        fprintf(fd, "rssi of last rcv[ext, ch1]: %u\n",
                stats->ast_rx_rssi_ext1);

    if (IS_RSSI_VALID(stats->ast_rx_rssi_ext2))
        fprintf(fd, "rssi of last rcv[ext, ch2]: %u\n",
                stats->ast_rx_rssi_ext2);



    STAT(be_xmit, "beacons transmitted");
    STAT(be_nobuf, "no skbuff available for beacon");
    STAT(per_cal, "periodic calibrations");
    STAT(per_calfail, "periodic calibration failures");
    STAT(per_rfgain, "rfgain value change");
    STAT(rate_calls, "rate control checks");
    STAT(rate_raise, "rate control raised xmit rate");
    STAT(rate_drop, "rate control dropped xmit rate");

    fprintf(fd, "Radio profile:\n");
    STAT(rx_num_data, "number of received data packets");
    STAT(rx_num_ctl, "number of received control packets");
    STAT(rx_num_mgmt, "number of received num mgmt packets");
    STAT(tx_hw_retries, "number of transmit retries in hardware");

    fprintf(fd, "Antenna profile:\n");
    STAT(ant_defswitch, "switched default/rx antenna");
    STAT(ant_txswitch, "tx antenna switches");
    STAT(chan_clr_cnt, "Channel clear count");
    STAT(cycle_cnt, "Cycle count");
    if (stats->ast_noise_floor)
        fprintf(fd, "%d Noise Floor\n", stats->ast_noise_floor);

    for (i = 0; i < 8; i++)
        if (stats->ast_ant_rx[i] || stats->ast_ant_tx[i])
            fprintf(fd, "[%u] tx %8u rx %8u\n", i,
                stats->ast_ant_tx[i], stats->ast_ant_rx[i]);


    STAT(bb_hang, "baseband hangs detected");
    STAT(mac_hang, "mac hangs detected");

#ifdef ATH_SUPPORT_UAPSD
    /*
     * UAPSD stats
     */
    if (stats->ast_uapsdqnul_pkts)
        fprintf(fd, "\nUAPSD stats\n");
    STAT_FMT(uapsdqnulbf_unavail,   "no qos null buffers available");
    STAT_FMT(uapsdqnul_pkts,        "qos null frames sent");
    STAT_FMT(uapsdqnulcomp,         "qos null frames completed");
    STAT_FMT(uapsdnodeinvalid,      "trigger for non-uapsd node");
    STAT_FMT(uapsddataqueued,       "qos data frames queued");
    STAT_FMT(uapsdeospdata,         "qos data with eosp sent");
    STAT_FMT(uapsddata_pkts,        "qos data frames sent");
    STAT_FMT(uapsddatacomp,         "qos data frames completed");
    STAT_FMT(uapsdedmafifofull,     "qos trigger failures edma fifo full");
#endif



    /*
     * 11n stats
     */
    fprintf(fd, "\n11n stats\n");
    STAT_11N(tx_pkts,            "total tx data packets");
    STAT_11N(tx_checks,          "tx drops in wrong state");
    STAT_11N(tx_drops,           "tx drops due to qdepth limit");
    STAT_11N(tx_minqdepth,       "tx when h/w queue depth is low");
    STAT_11N(tx_queue,           "tx pkts when h/w queue is busy");
    STAT_11N(tx_comps,           "tx completions");
    STAT_11N(tx_stopfiltered,    "tx pkts filtered for requeueing");
    STAT_11N(tx_qnull,           "txq empty occurences");
    STAT_11N(tx_noskbs,          "tx no skbs for encapsulations");
    STAT_11N(tx_nobufs,          "tx no descriptors");
    STAT_11N(tx_badsetups,       "tx key setup failures");
    STAT_11N(tx_normnobufs,      "tx no desc for legacy packets");
    STAT_11N(tx_schednone,       "tx schedule pkt queue empty");
    STAT_11N(tx_bars,            "tx bars sent");
    STAT_11N(txbar_compretries,  "tx bar retries sent");
    STAT_11N(txbar_errlast,      "tx bar last frame failed");
    STAT_11N(txbar_xretry,       "tx bar excessive retries");
    STAT_11N(tx_compunaggr,      "tx unaggregated frame completions");
    STAT_11N(txunaggr_xretry,    "tx unaggregated excessive retries");
    STAT_11N(txunaggr_compretries, "tx unaggregated unacked frames");
    STAT_11N(txunaggr_errlast,   "tx unaggregated last frame failed");
    STAT_11N(tx_compaggr,        "tx aggregated completions");
    STAT_11N(tx_bawadv,          "tx block ack window advanced");
    STAT_11N(tx_bawretries,      "tx block ack window retries");
    STAT_11N(tx_bawnorm,         "tx block ack window additions");
    STAT_11N(tx_bawupdates,      "tx block ack window updates");
    STAT_11N(tx_bawupdtadv,      "tx block ack window advances");
    STAT_11N(tx_retries,         "tx retries of sub frames");
    STAT_11N(tx_xretries,        "tx excessive retries of aggregates");
    STAT_11N(txaggr_noskbs,      "tx no skbs for aggr encapsualtion");
    STAT_11N(txaggr_nobufs,      "tx no desc for aggr");
    STAT_11N(txaggr_badkeys,     "tx enc key setup failures");
    STAT_11N(txaggr_schedwindow, "tx no frame scheduled: baw limited");
    STAT_11N(txaggr_single,      "tx frames not aggregated");
    STAT_11N(txaggr_mimo,        "tx frames aggregated for mimo");
    STAT_11N(txaggr_compgood,    "tx aggr good completions");
    STAT_11N(txaggr_compxretry,  "tx aggr excessive retries");
    STAT_11N(txaggr_compretries, "tx aggr unacked subframes");
    STAT_11N(txaggr_prepends,    "tx aggr old frames requeued");
    STAT_11N(txaggr_filtered,    "filtered aggr packet");
    STAT_11N(txaggr_fifo,        "fifo underrun of aggregate");
    STAT_11N(txaggr_xtxop,       "txop exceeded for an aggregate");
    STAT_11N(txaggr_desc_cfgerr, "aggregate descriptor config error");
    STAT_11N(txaggr_data_urun,   "data underrun for an aggregate");
    STAT_11N(txaggr_delim_urun,  "delimiter underrun for an aggregate");
    STAT_11N(txaggr_errlast,     "tx aggr: last sub-frame failed");
    STAT_11N(txaggr_longretries, "tx aggr: h/w long retries");
    STAT_11N(txaggr_shortretries,"tx aggr: h/w short retries");
    STAT_11N(txaggr_timer_exp,   "tx aggr: tx timer expired");
    STAT_11N(txaggr_babug,       "tx aggr: BA state is not updated");
    STAT_11N(txaggr_badtid,      "tx aggr: BA bad tid");
    STAT_11N(txrifs_single,      "tx frames not aggregated");
    STAT_11N(txrifs_babug,       "tx rifs: BA state is not updated");
    STAT_11N(txrifs_compretries, "tx rifs: unacked subframes");
    STAT_11N(txrifs_bar_alloc,   "tx rifs: bar frames allocated");
    STAT_11N(txrifs_bar_freed,   "tx rifs: bar frames freed");
    STAT_11N(txrifs_compgood,    "tx rifs: good completions");
    STAT_11N(tx_comprifs,        "tx rifs completions");
    STAT_11N(tx_compnorifs,      "tx non-rifs frame completions");
    STAT_11N(txrifs_prepends,    "tx rifs old frames requeued");
    STAT_11N(rx_pkts,            "rx pkts");
    STAT_11N(rx_aggr,            "rx aggregated packets");
    STAT_11N(rx_aggrbadver,      "rx pkts with bad version");
    STAT_11N(rx_bars,            "rx bars");
    STAT_11N(rx_nonqos,          "rx non qos-data frames");
    STAT_11N(rx_seqreset,        "rx sequence resets");
    STAT_11N(rx_oldseq,          "rx old packets");
    STAT_11N(rx_bareset,         "rx block ack window reset");
    STAT_11N(rx_baresetpkts,     "rx pts indicated due to baw resets");
    STAT_11N(rx_dup,             "rx duplicate pkts");
    STAT_11N(rx_baadvance,       "rx block ack window advanced");
    STAT_11N(rx_recvcomp,        "rx pkt completions");
    STAT_11N(rx_bardiscard,      "rx bar discarded");
    STAT_11N(rx_barcomps,        "rx pkts unblocked on bar reception");
    STAT_11N(rx_barrecvs,        "rx pkt completions on bar reception");
    STAT_11N(rx_skipped,         "rx pkt sequences skipped on timeout");
    STAT_11N(rx_comp_to,         "rx indications due to timeout");
    STAT_11N(wd_tx_active,       "watchdog: tx is active");
    STAT_11N(wd_tx_inactive,     "watchdog: tx is not active");
    STAT_11N(wd_tx_hung,         "watchdog: tx is hung");
    STAT_11N(wd_spurious,        "watchdog: spurious tx hang");
    STAT_11N(tx_requeue,         "filter & requeue on 20/40 transitions");
    STAT_11N(tx_drain_txq,       "draining tx queue on error");
    STAT_11N(tx_drain_tid,       "draining tid buf queue on error");
    STAT_11N(tx_cleanup_tid,     "draining tid buf queue on node cleanup");
    STAT_11N(tx_drain_bufs,      "buffers drained from pending tid queue");
    STAT_11N(tx_tidpaused,       "tid paused");
    STAT_11N(tx_tidresumed,      "tid resumed");
    STAT_11N(tx_unaggr_filtered, "unaggregated tx pkts filtered");
    STAT_11N(tx_aggr_filtered,   "aggregated tx pkts filtered");
    STAT_11N(tx_filtered,        "total sub-frames filtered");
    STAT_11N(rx_rb_on,           "rb on");
    STAT_11N(rx_rb_off,          "rb off");
    STAT_11N(rx_dsstat_err,      "rx descriptor status corrupted");
    STAT_11N(rx_timer_starts,    "rx timer starts");
    STAT_11N(rx_timer_stops,     "rx timer stops");
    STAT_11N(rx_timer_run,       "rx timer run");
    STAT_11N(rx_timer_more,      "rx timer more");
    STAT_11N(tx_deducted_tokens, "tx tokens deducted");
    STAT_11N(tx_unusable_tokens, "tx tokens unusable");

    /* Per Queue Statistics */
    for (i=0;i<10;++i) {
        if (stats->ast_txq_packets[i])
            fprintf(fd,"TXQ[%d]:%s tx %d xretry %d fifoerr %d filtered %d no buffs %d\n",
                    i,qdesc[i], stats->ast_txq_packets[i],stats->ast_txq_xretries[i],
                    stats->ast_txq_fifoerr[i],stats->ast_txq_filtered[i], stats->ast_txq_nobuf[i]);
    }

    /* Percentages */
    STAT_11N_P(txunaggr_xretry, tx_compunaggr,
               "tx unaggregated excessive retry percent");
    STAT_11N_P(txaggr_longretries, tx_compaggr,
               "tx aggregated long retry percent");
    STAT_11N_P(txaggr_compxretry, tx_compaggr,
               "tx aggregated excessive retry percent");
    STAT_11N_P(tx_retries, tx_bawadv,
               "tx aggregate subframe retry percent");
    STAT_11N_P(tx_xretries, tx_bawadv,
               "tx aggregate subframe excessive retry percent");
#ifdef ATH_SUPPORT_VOWEXT
    fprintf(fd, "VOW STATS: ul_tx_calls: %d %d %d %d ath_txq_calls: %d %d %d %d drops(be/bk): %d %d\n",
            stats->ast_vow_ul_tx_calls[0], stats->ast_vow_ul_tx_calls[1],
            stats->ast_vow_ul_tx_calls[2], stats->ast_vow_ul_tx_calls[3],
            stats->ast_vow_ath_txq_calls[0], stats->ast_vow_ath_txq_calls[1],
            stats->ast_vow_ath_txq_calls[2], stats->ast_vow_ath_txq_calls[3],
            stats->ast_vow_ath_be_drop, stats->ast_vow_ath_bk_drop);
#endif
#if UMAC_SUPPORT_VI_DBG
        fprintf(fd, "Timestamp  RSSIC0 RSSIC1 RSSIC2 RSSIE0 RSSIE1 RSSIE2  RSSI  EVM0 EVM1 EVM2 RXRATE TXFRAMECNT RXFRAMECNT RXCLRCOUNT RXEXCLRCNT CYCLECOUNT\n");
    for (i = 0; i < ATH_STATS_VI_LOG_LEN; i++) {
                fprintf(fd, "0x%08x %06d %06d %06d %06d %06d %06d %06d %4hhd %4hhd %4hhd 0x%04x %010d %010u %010u %010u %010u\n",
                             stats->vi_timestamp[i], stats->vi_rssi_ctl0[i], stats->vi_rssi_ctl1[i], stats->vi_rssi_ctl2[i],
                             stats->vi_rssi_ext0[i], stats->vi_rssi_ext1[i], stats->vi_rssi_ext2[i], stats->vi_rssi[i],
                             stats->vi_evm0[i], stats->vi_evm1[i], stats->vi_evm2[i], stats->vi_rs_rate[i],
                             stats->vi_tx_frame_cnt[i], stats->vi_rx_frame_cnt[i], stats->vi_rx_clr_cnt[i], stats->vi_rx_ext_clr_cnt[i],
                             stats->vi_cycle_cnt[i]);
                }
#endif

#ifdef ATH_SUPPORT_TxBF
    fprintf(fd,"\nHT Tx Rate STATS:\n");
    fprintf(fd," mcs 0- mcs 7 STATS:");
    for (i=0 ;i<8 ;i++)
        fprintf(fd,"%6d,",stats->ast_mcs_count[i]);
    fprintf(fd,"\n mcs 8- mcs15 STATS:");
    for (i=0 ;i<8 ;i++)
        fprintf(fd,"%6d,",stats->ast_mcs_count[i+8]);
    fprintf(fd,"\n mcs16- mcs23 STATS:");
    for (i=0 ;i<8 ;i++)
        fprintf(fd,"%6d,",stats->ast_mcs_count[i+16]);
    fprintf(fd, "\n");
        
    fprintf(fd, "\nAggregation STATS:\n");
    fprintf(fd, "subfr  1-8  STATS:");
    for (i = 1; i <= 8; i++)
        fprintf(fd, "%6d,", stats->ast_11n_stats.sub_frm[i]);
    fprintf(fd, "\n");
    fprintf(fd, "subfr  9-16 STATS:");
    for (i = 9; i <= 16; i++)
        fprintf(fd, "%6d,", stats->ast_11n_stats.sub_frm[i]);
    fprintf(fd, "\n");
    fprintf(fd, "subfr 17-24 STATS:");
    for (i = 17; i <= 24; i++)
        fprintf(fd, "%6d,", stats->ast_11n_stats.sub_frm[i]);
    fprintf(fd, "\n");
    fprintf(fd, "subfr 25-32 STATS:");
    for (i = 25; i <= 32; i++)
        fprintf(fd, "%6d,", stats->ast_11n_stats.sub_frm[i]);
    fprintf(fd, "\n");
    fprintf(fd, "subfr 0/>33 STATS:%6d,\n", stats->ast_11n_stats.sub_frm[0]);

    fprintf(fd, "\nReasons for limiting Aggregation:\n");
    fprintf(fd, "TxBF             :%6d,\n", stats->ast_11n_stats.aggr_limit_txbf);
    fprintf(fd, "Block Ack Window :%6d,\n", stats->ast_11n_stats.aggr_limit_baw);
    fprintf(fd, "Minrate Packet   :%6d,\n", stats->ast_11n_stats.aggr_limit_minrate);
    fprintf(fd, "Dynamic Pwrsave  :%6d,\n", stats->ast_11n_stats.aggr_limit_8k);
    fprintf(fd, "Size of Aggr     :%6d,\n", stats->ast_11n_stats.aggr_limit_size);
    fprintf(fd, "Frames in Aggr   :%6d,\n", stats->ast_11n_stats.aggr_limit_frames);
    fprintf(fd, "Short Packet     :%6d,\n", stats->ast_11n_stats.aggr_limit_pkt_size);
    fprintf(fd, "Queue Empty      :%6d,\n", stats->ast_11n_stats.aggr_limit_empty_q);

    fprintf(fd,"\nTxBF STATS:\n");
    fprintf(fd," Sounding sent %d\n",stats->ast_sounding_count);
    fprintf(fd," V/CV received %d\n",stats->ast_txbf_rpt_count);
#endif

#if ATH_RX_LOOPLIMIT_TIMER
    fprintf(fd, "LOOPLIMIT STATS:\n");
    fprintf(fd, " Rx looplimit timer start %d\n", stats->ast_rx_looplimit_start);
    fprintf(fd, " Rx looplimit timer end %d\n", stats->ast_rx_looplimit_end);
#endif

    for (i = MAX_BB_PANICS - 1; i >= 0; i--) {
        if (!stats->ast_bb_panic[i].valid)
            continue;

        fprintf(fd, "\n==== BB update: BB status=0x%08x, tsf=0x%08x ====\n",
            stats->ast_bb_panic[i].status, stats->ast_bb_panic[i].tsf);
        fprintf(fd, "** BB state: wd=%u det=%u rdar=%u rOFDM=%d rCCK=%u "
            "tOFDM=%u tCCK=%u agc=%u src=%u **\n", stats->ast_bb_panic[i].wd, 
            stats->ast_bb_panic[i].det, stats->ast_bb_panic[i].rdar,
            stats->ast_bb_panic[i].r_odfm, stats->ast_bb_panic[i].r_cck, 
            stats->ast_bb_panic[i].t_odfm, stats->ast_bb_panic[i].t_cck, 
            stats->ast_bb_panic[i].agc, stats->ast_bb_panic[i].src);
        fprintf(fd, "** BB WD cntl: cntl1=0x%08x cntl2=0x%08x **\n",
            stats->ast_bb_panic[i].phy_panic_wd_ctl1, 
            stats->ast_bb_panic[i].phy_panic_wd_ctl2);
        fprintf(fd, "** BB mode: BB_gen_controls=0x%08x **\n", 
            stats->ast_bb_panic[i].phy_gen_ctrl);
        if (stats->ast_bb_panic[i].cycles) {
            fprintf(fd, "** BB busy times: rx_clear=%d%%, "
                "rx_frame=%d%%, tx_frame=%d%% **\n", 
                stats->ast_bb_panic[i].rxc_pcnt, 
                stats->ast_bb_panic[i].rxf_pcnt, 
                stats->ast_bb_panic[i].txf_pcnt);
        }
        fprintf(fd, "==== BB update: done ====\n\n");
    }


    if (stats->ast_dfs_stats.dfs_stats_valid) {
        fprintf(fd, "DFS Statistics\n");
        fprintf(fd, "Radar Event Reported by PHY: %d\n", stats->ast_dfs_stats.event_count);
        fprintf(fd, "Chirping Pulses Detected: %d\n", stats->ast_dfs_stats.chirp_count);

        fprintf(fd, "Number of filters=%d\n",
        stats->ast_dfs_stats.num_filter);

        for (i=0; i < stats->ast_dfs_stats.num_filter; i++) {
            fprintf(fd, "filterID = %d PRI threshold reached=%u; Duration threshold reached=%u; RSSI threshold reached=%u\n",
                stats->ast_dfs_stats.fstat[i].filter_id,  
                stats->ast_dfs_stats.fstat[i].pri_threshold_reached, 
                stats->ast_dfs_stats.fstat[i].dur_threshold_reached, 
                stats->ast_dfs_stats.fstat[i].rssi_threshold_reached);
        }
    }


#undef STAT_FMT
#undef STAT
#undef STAT64
#undef STAT_PEEK_11N
#undef STAT_11N_P
#undef STAT_11N
#undef N
}

static int signalled;

static void
catchalarm(int signo)
{
    signalled = 1;
}

#if ATH_PERF_PWR_OFFLOAD
static void
ol_txrx_printstats(FILE *fd, const struct ol_txrx_stats *stats,
                          int stats_level)

{
    fprintf(fd, "txrx stats:\n");
    if (stats_level == TXRX_STATS_LEVEL_BASIC) {
        fprintf(fd,"  tx: %u msdus (%u B)\n",
            stats->tx.delivered.pkts,
            stats->tx.delivered.bytes);
    } else { /* full */
        fprintf(fd,
            "  tx: sent %u msdus (%u B), "
            "rejected %u (%u B), dropped %u (%u B)\n",
            stats->tx.delivered.pkts,
            stats->tx.delivered.bytes,
            stats->tx.dropped.host_reject.pkts,
            stats->tx.dropped.host_reject.bytes,
            stats->tx.dropped.download_fail.pkts
              + stats->tx.dropped.target_discard.pkts
              + stats->tx.dropped.no_ack.pkts,
            stats->tx.dropped.download_fail.bytes
              + stats->tx.dropped.target_discard.bytes
              + stats->tx.dropped.no_ack.bytes);
        fprintf(fd,
            "    download fail: %u (%u B), "
            "target discard: %u (%u B), "
            "no ack: %u (%u B)\n",
            stats->tx.dropped.download_fail.pkts,
            stats->tx.dropped.download_fail.bytes,
            stats->tx.dropped.target_discard.pkts,
            stats->tx.dropped.target_discard.bytes,
            stats->tx.dropped.no_ack.pkts,
            stats->tx.dropped.no_ack.bytes);
    }
    fprintf(fd,
        "  rx: %u msdus, %u bytes\n",
        stats->rx.delivered.pkts,
        stats->rx.delivered.bytes);
    if (stats_level == TXRX_STATS_LEVEL_FULL) {
        fprintf(fd,
            "    forwarded %u msdus, %u bytes\n",
            stats->rx.forwarded.pkts,
            stats->rx.forwarded.bytes);
    }
}

static void
ol_ath_stats_print(const struct wlan_dbg_stats *wlan_pdev_stats, FILE *fd)
{
   const struct wlan_dbg_tx_stats *tx = &wlan_pdev_stats->tx;
   const struct wlan_dbg_rx_stats *rx = &wlan_pdev_stats->rx;
    fprintf(fd,"\n### Tx ###\n");

    /* Num HTT cookies queued to dispatch list */
	fprintf(fd,"comp_queued       :\t%d\n",tx->comp_queued);
    /* Num HTT cookies dispatched */
    fprintf(fd,"comp_delivered    :\t%d\n",tx->comp_delivered);
    /* Num MSDU queued to WAL */
    fprintf(fd,"msdu_enqued       :\t%d\n",tx->msdu_enqued);
    /* Num MSDUs dropped by WMM limit */
    fprintf(fd,"wmm_drop          :\t%d\n",tx->wmm_drop);
    /* Num Local frames queued */
    fprintf(fd,"local_enqued      :\t%d\n",tx->local_enqued);
    /* Num Local frames done */
    fprintf(fd,"local_freed       :\t%d\n",tx->local_freed);
    /* Num queued to HW */
    fprintf(fd,"hw_queued         :\t%d\n",tx->hw_queued);
    /* Num PPDU reaped from HW */
    fprintf(fd,"hw_reaped         :\t%d\n",tx->hw_reaped);
    /* Num underruns */
    fprintf(fd,"underrun          :\t%d\n",tx->underrun);
    /* Num PPDUs cleaned up in TX abort */
   	fprintf(fd,"tx_abort          :\t%d\n",tx->tx_abort);
    /* Num MPDUs requed by SW */
   	fprintf(fd,"mpdus_requed      :\t%d\n",tx->mpdus_requed);
    /* Excessive retries */
   	fprintf(fd,"excess retries    :\t%d\n",tx->tx_xretry);
    /* last data rate */
   	fprintf(fd,"last rc           :\t%d\n",tx->data_rc);
    /* scheduler self triggers */
   	fprintf(fd,"sched self trig   :\t%d\n",tx->self_triggers);
    fprintf(fd,"\n### Rx ###\n");
    /* Cnts any change in ring routing mid-ppdu */
	//      qdf_print("ppdu_route_change :\t%d\n",rx->mid_ppdu_route_change);
    /* Total number of statuses processed */
    fprintf(fd,"status_rcvd       :\t%d\n",rx->status_rcvd);
    /* Extra frags on rings 0-3 */
    fprintf(fd,"r0_frags          :\t%d\n",rx->r0_frags);
    fprintf(fd,"r1_frags          :\t%d\n",rx->r1_frags);
    fprintf(fd,"r2_frags          :\t%d\n",rx->r2_frags);
    //fprintf(fd,"r3_frags          :\t%d\n",rx->r3_frags);
    /* MSDUs / MPDUs delivered to HTT */
    fprintf(fd,"htt_msdus         :\t%d\n",rx->htt_msdus);
    fprintf(fd,"htt_mpdus         :\t%d\n",rx->htt_mpdus);
    /* MSDUs / MPDUs delivered to local stack */
    fprintf(fd,"loc_msdus         :\t%d\n",rx->loc_msdus);
    fprintf(fd,"loc_mpdus         :\t%d\n",rx->loc_mpdus);
    /* AMSDUs that have more MSDUs than the status ring size */
    fprintf(fd,"oversize_amsdu    :\t%d\n",rx->oversize_amsdu);
    /* Number of PHY errors */
    fprintf(fd,"phy_errs          :\t%d\n",rx->phy_errs);
    /* Number of PHY errors dropped */
    fprintf(fd,"phy_errs dropped  :\t%d\n",rx->phy_err_drop);
    /* Number of mpdu errors - FCS, MIC, ENC etc. */
    fprintf(fd,"mpdu_errs         :\t%d\n",rx->mpdu_errs);

}

static void
ol_radiostats_print(const struct ol_ath_radiostats *radio_stats, const struct wlan_dbg_stats *wlan_pdev_stats, FILE *fd)
{
    const struct wlan_dbg_tx_stats *tx = &wlan_pdev_stats->tx;
    int   i;

    fprintf(fd,"ast_be_xmit         :\t%llu\n",radio_stats->tx_beacon);
    fprintf(fd,"ast_be_nobuf        :\t%d\n",radio_stats->be_nobuf);
    fprintf(fd,"ast_tx_buf_count    :\t%u\n",radio_stats->tx_buf_count);
    fprintf(fd,"ast_tx_packets      :\t%u\n",radio_stats->tx_mgmt + radio_stats->tx_num_data);
    fprintf(fd,"ast_rx_packets      :\t%u\n",radio_stats->rx_packets);
    fprintf(fd,"ast_tx_mgmt         :\t%d\n",radio_stats->tx_mgmt);
    fprintf(fd,"ast_tx_nobuf        :\t%d\n",tx->wmm_drop);
    fprintf(fd,"ast_tx_xretries     :\t%u\n",tx->tx_xretry);
    fprintf(fd,"ast_rx_num_data     :\t%u\n",radio_stats->rx_num_data);
    fprintf(fd,"ast_rx_num_mgmt     :\t%u\n",radio_stats->rx_num_mgmt);
    fprintf(fd,"ast_rx_num_ctl      :\t%u\n",radio_stats->rx_num_ctl);
    fprintf(fd,"ast_tx_rssi         :\t%u\n",radio_stats->tx_rssi);
    fprintf(fd,"ast_rx_rssi_comb    :\t%u\n",radio_stats->rx_rssi_comb);
    fprintf(fd,"ast_rx_rssi_chain0  :\t%d",radio_stats->rx_rssi_chain0.rx_rssi_pri20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain0.rx_rssi_sec20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain0.rx_rssi_sec40);
    fprintf(fd,"\t%d\n",radio_stats->rx_rssi_chain0.rx_rssi_sec80);
    fprintf(fd,"ast_rx_rssi_chain1  :\t%d",radio_stats->rx_rssi_chain1.rx_rssi_pri20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain1.rx_rssi_sec20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain1.rx_rssi_sec40);
    fprintf(fd,"\t%d\n",radio_stats->rx_rssi_chain1.rx_rssi_sec80);
    fprintf(fd,"ast_rx_rssi_chain2  :\t%d",radio_stats->rx_rssi_chain2.rx_rssi_pri20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain2.rx_rssi_sec20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain2.rx_rssi_sec40);
    fprintf(fd,"\t%d\n",radio_stats->rx_rssi_chain2.rx_rssi_sec80);
    fprintf(fd,"ast_rx_rssi_chain3  :\t%d",radio_stats->rx_rssi_chain3.rx_rssi_pri20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain3.rx_rssi_sec20);
    fprintf(fd,"\t%d",radio_stats->rx_rssi_chain3.rx_rssi_sec40);
    fprintf(fd,"\t%d\n",radio_stats->rx_rssi_chain3.rx_rssi_sec80);
    fprintf(fd,"ast_rx_bytes        :\t%llu\n",radio_stats->rx_bytes);
    fprintf(fd,"ast_tx_bytes        :\t%llu\n",radio_stats->tx_bytes);
    fprintf(fd,"tx_compaggr         :\t%u\n",radio_stats->tx_compaggr);
    fprintf(fd,"rx_aggr             :\t%u\n",radio_stats->rx_aggr);
    fprintf(fd,"tx_retries          :\t%d\n",tx->mpdus_requed);
    fprintf(fd,"tx_xretries         :\t%u\n",tx->sw_retry_failure);
    fprintf(fd,"tx_bawadv           :\t%u\n",radio_stats->tx_bawadv);
    fprintf(fd,"tx_compunaggr       :\t%u\n",radio_stats->tx_compunaggr);
    fprintf(fd,"ast_rxorn           :\t%u\n",radio_stats->rx_overrun);
    fprintf(fd,"ast_txurn           :\t%d\n",tx->underrun);
    fprintf(fd,"ast_txto            :\t%u\n",tx->pdev_tx_timeout);
    fprintf(fd,"ast_mib             :\t%u\n",radio_stats->mib_int_count);
    fprintf(fd,"ast_rx_badcrypt     :\t%u\n",radio_stats->rx_badcrypt);
    fprintf(fd,"ast_rx_badmic       :\t%u\n",radio_stats->rx_badmic);
#if ATH_RX_LOOPLIMIT_TIMER
    fprintf(fd,"rx_looplimit_start  :\t%lu\n",radio_stats->rx_looplimit_start);
    fprintf(fd,"rx_looplimit_end    :\t%lu\n",radio_stats->rx_looplimit_end);
#endif
    fprintf(fd,"target assert count :\t%u\n",radio_stats->tgt_asserts);
    fprintf(fd,"noise floor         :\t%hd\n",radio_stats->chan_nf);
    fprintf(fd,"noise floor (sec 80):\t%hd\n",radio_stats->chan_nf_sec80);
    fprintf(fd,"Last MSDU unset cnt :\t%hd\n", radio_stats->rx_last_msdu_unset_cnt);
    
    fprintf(fd," Rx MCS STATS:\n");
    fprintf(fd," mcs 0- mcs 4 STATS:");
#define PRINT_ROW_ELEM 5
    for (i=0 ;i < PRINT_ROW_ELEM ;i++)
        fprintf(fd,"%6d,",radio_stats->rx_mcs[i]);
    fprintf(fd,"\n mcs 5- mcs 9 STATS:");
    for (i=0 ;i < PRINT_ROW_ELEM ;i++)
        fprintf(fd,"%6d,",radio_stats->rx_mcs[i + PRINT_ROW_ELEM]);
    fprintf(fd, "\n");
    
    fprintf(fd," Tx MCS STATS:\n");
    fprintf(fd," mcs 0- mcs 4 STATS:");
    for (i=0 ;i < PRINT_ROW_ELEM ;i++)
        fprintf(fd,"%6d,",radio_stats->tx_mcs[i]);
    fprintf(fd,"\n mcs 5- mcs 9 STATS:");
    for (i=0 ;i < PRINT_ROW_ELEM ;i++)
        fprintf(fd,"%6d,",radio_stats->tx_mcs[i + PRINT_ROW_ELEM]);
    fprintf(fd, "\n");
#undef PRINT_ROW_ELEM
}

static void
ol_tidq_stats_print(struct wlan_dbg_tidq_stats *wal_pdev_tidq_stats, FILE *fd)
{
    struct wlan_dbg_txq_stats *tidq_st = &wal_pdev_tidq_stats->txq_st;
    int i = 0;

    fprintf(fd, "\n");
    fprintf(fd," WAL TID QUEUE STATS PER H/W Q \n");
    if(wal_pdev_tidq_stats->wlan_dbg_tid_txq_status == 1)
      printf(" Could not read TIDQ stats from firmware \n");
    else
    {
     fprintf(fd," ============================= \n");
     fprintf(fd,"   Frames queued to h/w Q \n");
     for (i=0; i < 10; i++)
       fprintf(fd,"\tQ%d",i);
     fprintf(fd,"\n");
     for (i=0; i < DBG_STATS_MAX_HWQ_NUM; i++){
        fprintf(fd,"\t%d", (unsigned short)tidq_st->num_pkts_queued[i]);
     }
     fprintf(fd,"\n TID Queue stats \n");
     fprintf(fd," S/W queue stats <---> H/W queue stats\n");
     fprintf(fd,"\t------------------------------\n");
     for(i=0; i< DBG_STATS_MAX_TID_NUM; i++)
     {
      fprintf(fd,"TID %d\t%d\t\t%d\n",i,tidq_st->tid_sw_qdepth[i], tidq_st->tid_hw_qdepth[i]);
     }
     fprintf(fd,"\n\t------------------------------\n");
    }
}

static void
ol_printstats(FILE *fd, const struct ol_stats *ath_stats)
{
    ol_ath_stats_print(&ath_stats->stats, stdout);
    ol_txrx_printstats(fd, &ath_stats->txrx_stats, ath_stats->txrx_stats_level); 
    ol_radiostats_print(&ath_stats->interface_stats, &ath_stats->stats, stdout);
}
#endif

static void print_usage(void)
{
  printf("athstats [-e] -i <interface>\n");
}

int
main(int argc, char *argv[])
{
#ifdef __linux__
    const char *ifname = "wifi0";
#else
    const char *ifname = "ath0";
#endif
    int s, i, c, index;
    struct ifreq ifr;
#if ATH_PERF_PWR_OFFLOAD
#define max(a, b) (((a) > (b)) ? a : b)
    int buf_sz = max(sizeof(struct ath_stats), sizeof(struct ol_stats));
#else
    int buf_sz = sizeof(struct ath_stats);
#endif
    char buffer[buf_sz];
    struct ath_stats_container asc = {0};
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        err(1, "socket");

    opterr = 0;
    while ((c = getopt(argc, argv, "ei:")) != -1)
      switch (c)
        {
        case 'i':
          ifname = optarg;
          break;
        case 'e':
          asc.flag_ext = EXT_TXRX_FW_STATS;
          break;
        case '?':
          if (optopt == 'i')
              fprintf(stderr, "Option -%c requires an argument.\n", optopt);
          close(s);
          return -1;
        default:
          print_usage();
          abort();
        }

    for (index = optind; index < argc; index++) {
      printf ("Non-option argument %s\n", argv[index]);
      print_usage();
      close(s);
      return -1;
    }

    if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name))
                                        >= sizeof(ifr.ifr_name)) {
       fprintf(stderr, "Error copying ifname\n");
       close(s);
       return -1;
    }

    asc.size = buf_sz;
    asc.address = (struct ath_stats *)buffer;
    asc.offload_if = -1;
    ifr.ifr_data = (caddr_t) &asc;
    if (ioctl(s, SIOCGATHSTATS, &ifr) < 0)
        err(1, "%s", ifr.ifr_name);

    if (asc.offload_if == 0) {
        struct ath_stats *stats = (struct ath_stats *)buffer;
        struct ath_phy_stats phystats[WIRELESS_MODE_MAX];
        struct ath_phy_stats cur_phystats = { 0 };
        struct ath_phy_stats_container apsc;
        struct phy_radiolevel_stats phy_radiostats = { 0 };

        printstats(stdout, stats);

        memset(phystats, 0, sizeof(phystats));
        ifr.ifr_data = (caddr_t) &phystats;
        if (ioctl(s, SIOCGATHPHYSTATS, &ifr) < 0) {
            perror("SIOCGATHPHYSTATS");
            close(s);
            return -1;
        }
        for (i = 0; i < WIRELESS_MODE_MAX; i++) {
            phy_radiostats.rx_phyerr += phystats[i].ast_rx_phyerr;
            phy_radiostats.rx_crcerr += phystats[i].ast_rx_crcerr;
            phy_radiostats.rx_decrypterr += phystats[i].ast_rx_decrypterr;
            phy_radiostats.rx_demicerr += phystats[i].ast_rx_demicerr;
            phy_radiostats.rx_fifoerr += phystats[i].ast_rx_fifoerr;
            phy_radiostats.rx_decrypt_busyerr += phystats[i].ast_rx_decrypt_busyerr;
        }
        apsc.size = sizeof(struct ath_phy_stats);
        apsc.address = &cur_phystats;

        ifr.ifr_data = (caddr_t) &apsc;
        if (ioctl(s, SIOCGATHPHYSTATSCUR, &ifr) < 0) {
            perror("SIOCGATHPHYSTATSCUR");
            close(s);
            return -1;
        }
        printphy_stats(stdout, &phy_radiostats);
        printphy_stats_curmode(stdout, &cur_phystats);
        print_mib_stats(stdout, stats);
#if ATH_PERF_PWR_OFFLOAD
    } else if (asc.offload_if == 1) {
        struct ol_stats *ath_stats = (struct ol_stats *)buffer;
        ol_printstats(stdout, (const struct ol_stats *)ath_stats);
        if (asc.flag_ext & EXT_TXRX_FW_STATS)
          ol_tidq_stats_print(&ath_stats->tidq_stats, stdout);
#endif
    }
    close(s);
    return 0;
}
