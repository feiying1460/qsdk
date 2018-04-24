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

#ifndef _DEV_OL_ATH_UTF_H
#define _DEV_OL_ATH_UTF_H

#include <osdep.h>
#include <a_types.h>
#include <a_osapi.h>
#include <ol_if_ath_api.h>

#define MAX_UTF_EVENT_LENGTH 2048
#define MAX_WMI_UTF_LEN      252


typedef struct {
    A_UINT32 len;
    A_UINT32 msgref;
    A_UINT32 segmentInfo;
    A_UINT32 pad;
} SEG_HDR_INFO_STRUCT;

int ol_ath_utf_cmd(ol_scn_t scn_handle, u_int8_t *data, u_int16_t len);
int ol_ath_utf_rsp(ol_scn_t scn, u_int8_t *payload);

#endif
