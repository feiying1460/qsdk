#ifndef IEEE80211_IOCTL_ACFG_H
#define IEEE80211_IOCTL_ACFG_H

#include <linux/wireless.h>
#include <linux/etherdevice.h>
#include <net/iw_handler.h>
#include <acfg_api_types.h>
#include <qdf_atomic.h>
#include <acfg_event_types.h>

#if UMAC_SUPPORT_ACFG

#define ACFG_PVT_IOCTL  (SIOCWANDEV)

#if ACFG_NETLINK_TX

extern struct ath_softc_net80211 *global_scn[10];
extern int num_global_scn;
extern struct ol_ath_softc_net80211 *ol_global_scn[10];
extern int ol_num_global_scn;

typedef struct acfg_netlink_pvt {
    void *acfg_sock;
    qdf_semaphore_t *sem_lock;
    qdf_spinlock_t offchan_lock;
    qdf_nbuf_queue_t offchan_list;
    struct timer_list offchan_timer;
    u_int8_t home_chan;
    struct acfg_offchan_resp acfg_resp;
    struct acfg_offchan_tx_status acfg_tx_status[ACFG_MAX_OFFCHAN_TX_FRAMES];
    int process_pid;
    acfg_offchan_stat_t offchan_stat;
    qdf_atomic_t num_cmpl_pending;
    struct ieee80211vap *vap;
    int scanid_tx;
    int scanid_rx;
    qdf_atomic_t in_lock;
} acfg_netlink_pvt_t;

#endif

typedef struct acfg_diag_stainfo {
    TAILQ_ENTRY(acfg_diag_stainfo) next;
    int64_t seconds;
    uint8_t notify;
    struct ieee80211vap *vap;
    acfg_diag_event_t diag;
}acfg_diag_stainfo_t;

typedef struct acfg_diag_pvt
{
    TAILQ_HEAD(, acfg_diag_stainfo) curr_stas;
    TAILQ_HEAD(, acfg_diag_stainfo) prev_stas;
    struct timer_list diag_timer;
}acfg_diag_pvt_t;

int
acfg_handle_vap_ioctl(struct net_device *dev, void *data);
void acfg_offchan_tx_drain(acfg_netlink_pvt_t *acfg_nl);

#else
#define acfg_handle_vap_ioctl(dev, data) {}
#endif

#endif /*IEEE80211_IOCTL_ACFG_H*/
