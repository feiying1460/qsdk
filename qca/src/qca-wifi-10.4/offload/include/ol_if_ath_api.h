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

/*
 * Defintions for the Atheros Wireless LAN controller driver.
 */
#ifndef _DEV_OL_ATH_API_H
#define _DEV_OL_ATH_API_H

#include <osdep.h>
#include "ol_defines.h"
#include "wbuf.h"
#include "htc_api.h"
#include "wmi.h"

A_STATUS ol_ath_send(ol_scn_t scn, wbuf_t wbuf, HTC_ENDPOINT_ID eid);
int
ol_ath_ready_event(ol_scn_t scn_handle, uint8_t *ev, uint16_t len);
int
ol_ath_service_ready_event(ol_scn_t scn_handle, uint8_t *evt_buf, uint16_t len);

#ifdef ATH_SUPPORT_HYFI_ENHANCEMENTS
int ol_ath_node_ext_stats_enable(struct ieee80211_node *ni, u_int32_t enable);
#endif
#endif /* _DEV_OL_ATH_API_H  */
