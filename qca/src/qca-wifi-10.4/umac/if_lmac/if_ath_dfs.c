/*
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <ieee80211_channel.h>
#include <ieee80211_var.h>
#include <ieee80211_scan.h>
#include <ieee80211_resmgr.h>

#include "ieee80211_sme_api.h"
#include "ieee80211_sm.h"
#include "if_athvar.h"

#if UMAC_SUPPORT_DFS

/*
 * Print a console message with the device name prepended.
 */
void
if_printf( osdev_t dev, const char *fmt, ...)
{
    va_list ap;
    char buf[512];              /* XXX */

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    printk("\n %s\n", buf);     /* TODO: print device name also */
}

static void
change_channel(struct ieee80211com *ic,
	       struct ieee80211_channel *chan)
{
    ic->ic_curchan = chan;
    ic->ic_set_channel(ic);
}

#else

void
ieee80211_mark_dfs(struct ieee80211com *ic, struct ieee80211_channel *ichan)
{
    return;
}

#if ATH_SUPPORT_IBSS_DFS
void ieee80211_ibss_beacon_update_start(struct ieee80211com *ic)
{
    return;
}

void ieee80211_ibss_beacon_update_stop(struct ieee80211com *ic)
{
    return;
}
#endif /* ATH_SUPPORT_IBSS_DFS */

#endif    // UMAC_SUPPORT_DFS
