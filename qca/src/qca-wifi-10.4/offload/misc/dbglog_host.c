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
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc
 */

/* Host Debug log implementation */


#include "ol_if_athvar.h"
#include "athdefs.h"
#include "a_types.h"
#include "a_osapi.h"
#include "a_debug.h"
#include "ol_defines.h"
#include "ol_if_ath_api.h"
#include "ol_helper.h"
#include "qdf_mem.h"
#include "dbglog_host.h"
#include "wmi.h"
#include "wmi_unified_api.h"
#include <pktlog_ac_api.h>
#include <dbglog_rtt_host.h>

#include <hif_main.h>
#define DBGLOG_PRINT_PREFIX "FWLOG: "
#define MAX_DBG_MSGS 256
#include "dbglog_host_gen.h"
#include "wmi_unified.h"

module_dbg_print mod_print[WLAN_MODULE_ID_MAX];
dbglog_prt_path_t dbglog_prt_path;

#if OL_ATH_SMART_LOGGING
extern uint8_t * hif_log_dump_ce(struct hif_softc *scn, uint8_t *file_cur,
                                    uint8_t *file_init, uint32_t file_sz,
                                    uint32_t ce, uint32_t smart_log_skb_sz);
#define SMART_LOG_MEM (16*PAGE_SIZE)
#define SMART_LOG_RING_GAURD 10
#endif /* OL_ATH_SMART_LOGGING */

#if DBGLOG_WQ_BASED
/*default rate limit period - 2sec*/
#define DBGLOG_PRINT_RATE_LIMIT_PERIOD (2*HZ)
/*default burst for rate limit */
#define DBGLOG_PRINT_RATE_LIMIT_BURST_DEFAULT   250
DEFINE_RATELIMIT_STATE(dbglog_ratelimit, DBGLOG_PRINT_RATE_LIMIT_PERIOD,
                DBGLOG_PRINT_RATE_LIMIT_BURST_DEFAULT);

int
static dbglog_ratelimit_print(void)
{
    if (dbglog_ratelimit.burst == 0) {
        return 1;
    } else {
        return __ratelimit(&dbglog_ratelimit);
    }
}
#else
#define dbglog_ratelimit_print() 1
#endif

/*Log debug header params when wrong params recieved from FW*/
static inline void dbglog_num_args_err (int mod_id, int vap_id, int dbg_id, int num_args) {
    if (dbglog_ratelimit_print()) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
            "mod_id %d dbg_id %d, num_args rcvd %d\n", mod_id, dbg_id, num_args);
    }
}

A_STATUS
wmi_config_debug_module_cmd(ol_scn_t scn,
                            struct dbglog_config_msg_s *config);


void dbglog_module_log_enable(ol_scn_t scn, A_UINT32 mod_id,
                  bool isenable)
{
    struct dbglog_config_msg_s configmsg;

    if (mod_id > WLAN_MODULE_ID_MAX) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dbglog_module_log_enable: Invalid module id %d\n",
                mod_id);
        return;
    }

    OS_MEMSET(&configmsg, 0, sizeof(struct dbglog_config_msg_s));

    if (isenable)
        DBGLOG_MODULE_ENABLE(configmsg.config.mod_id, mod_id);

    configmsg.cfgvalid[mod_id/32] = (1 << (mod_id % 32));
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "cfg valid value inside module enable %0x",configmsg.cfgvalid[0]);
    wmi_config_debug_module_cmd(scn, &configmsg);
}

void dbglog_vap_log_enable(ol_scn_t scn, A_UINT16 vap_id,
               bool isenable)
{
    struct dbglog_config_msg_s configmsg;

    if (vap_id > DBGLOG_MAX_VAPID) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "dbglog_vap_log_enable:Invalid vap_id %d\n",
        vap_id);
        return;
    }

    OS_MEMSET(&configmsg, 0, sizeof(struct dbglog_config_msg_s));

    if (isenable)
        DBGLOG_VAP_ENABLE(configmsg.config.dbg_config, vap_id);

    configmsg.cfgvalid[DBGLOG_MODULE_BITMAP_SIZE] = (1 << (vap_id +
                             DBGLOG_VAP_LOG_ENABLE_OFFSET));
    wmi_config_debug_module_cmd(scn, &configmsg);

}

void dbglog_set_log_lvl(ol_scn_t scn, DBGLOG_LOG_LVL log_lvl)
{
    struct dbglog_config_msg_s configmsg;

    OS_MEMSET(&configmsg, 0, sizeof(struct dbglog_config_msg_s));
    DBGLOG_LOG_LVL_ENABLE(configmsg.config.dbg_config, log_lvl);
    configmsg.cfgvalid[DBGLOG_MODULE_BITMAP_SIZE] = DBGLOG_LOG_LVL_ENABLE_MASK;
    wmi_config_debug_module_cmd(scn, &configmsg);
}

void dbglog_reporting_enable(ol_scn_t scn, bool isenable)
{
    struct dbglog_config_msg_s configmsg;

    OS_MEMSET(&configmsg, 0, sizeof(struct dbglog_config_msg_s));

     if (isenable)
        DBGLOG_REPORTING_ENABLE(configmsg.config.dbg_config);

    configmsg.cfgvalid[DBGLOG_MODULE_BITMAP_SIZE] = DBGLOG_REPORTING_ENABLE_MASK;
    wmi_config_debug_module_cmd(scn, &configmsg);
}

void dbglog_set_timestamp_resolution(ol_scn_t scn, A_UINT16 tsr)
{
    struct dbglog_config_msg_s configmsg;

    OS_MEMSET(&configmsg, 0, sizeof(struct dbglog_config_msg_s));
    DBGLOG_TIMESTAMP_RES_SET(configmsg.config.dbg_config, tsr);
    configmsg.cfgvalid[DBGLOG_MODULE_BITMAP_SIZE] = DBGLOG_TIMESTAMP_RESOLUTION_MASK;
    wmi_config_debug_module_cmd(scn, &configmsg);
}

void dbglog_set_report_size(ol_scn_t scn, A_UINT16 size)
{
    struct dbglog_config_msg_s configmsg;

    OS_MEMSET(&configmsg, 0, sizeof(struct dbglog_config_msg_s));
    DBGLOG_REPORT_SIZE_SET(configmsg.config.dbg_config, size);
    configmsg.cfgvalid[DBGLOG_MODULE_BITMAP_SIZE] = DBGLOG_REPORT_SIZE_MASK;
    wmi_config_debug_module_cmd(scn, &configmsg);
}

A_STATUS
wmi_config_debug_module_cmd(ol_scn_t scn, struct dbglog_config_msg_s *configmsg)
{
    struct dbglog_params param;
    int status;

    qdf_mem_set(&param, sizeof(param), 0);
    param.cfgvalid[0] = configmsg->cfgvalid[0];
    param.cfgvalid[1] = configmsg->cfgvalid[1];
    param.cfgvalid[2] = configmsg->cfgvalid[2];
    param.val = configmsg->config.dbg_config;
    param.module_id_bitmap = &(configmsg->config.mod_id[0]);

    status = wmi_unified_dbglog_cmd_send(scn->wmi_handle, &param);

    return status;
}

static char *
dbglog_get_msg(A_UINT32 moduleid, A_UINT32 debugid)
{
    static char unknown_str[64];

    if (moduleid < WLAN_MODULE_ID_MAX && debugid < MAX_DBG_MSGS) {
        char *str = DBG_MSG_ARR[moduleid][debugid];
        if (str && str[0] != '\0') {
            return str;
        }
    }

    snprintf(unknown_str, sizeof(unknown_str),
            "UNKNOWN %u:%u",
            moduleid, debugid);

    return unknown_str;
}

void
dbglog_printf(
        A_UINT32 timestamp,
        A_UINT16 vap_id,
        const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    /* treat complete message as one print */
    if( !dbglog_ratelimit_print() ) {
        return;
    }

    if (vap_id < DBGLOG_VAPID_NUM_MAX) {
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, DBGLOG_PRINT_PREFIX "[%u] vap-%u ", timestamp, vap_id);
        } else {
            snprintf(buf, sizeof(buf), DBGLOG_PRINT_PREFIX "[%u] vap-%u ", timestamp, vap_id);
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
    } else {
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, DBGLOG_PRINT_PREFIX "[%u] ", timestamp);
        } else {
            snprintf(buf, sizeof(buf), DBGLOG_PRINT_PREFIX "[%u] ", timestamp);
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s\n", buf);

    if (dbglog_prt_path == DBGLOG_PRT_PKTLOG) {
#ifndef REMOVE_PKT_LOG
        if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
        }
#endif
    }
}

#define USE_NUMERIC 0

A_BOOL
dbglog_default_print_handler(A_UINT32 mod_id, A_UINT16 vap_id,
                            A_UINT32 dbg_id, A_UINT32 timestamp,
                            A_UINT16 numargs, A_UINT32 *args)
{
    int i;
    char buf[512];

    /* treat complete message as one print */
    if( !dbglog_ratelimit_print() ) {
        return FALSE;
    }

    if (vap_id < DBGLOG_VAPID_NUM_MAX) {
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, DBGLOG_PRINT_PREFIX "[%u] vap-%u %s ( ", timestamp, vap_id, dbglog_get_msg(mod_id, dbg_id));
        } else {
            snprintf(buf, sizeof(buf), DBGLOG_PRINT_PREFIX "[%u] vap-%u %s ( ", timestamp, vap_id, dbglog_get_msg(mod_id, dbg_id));
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
    } else {
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, DBGLOG_PRINT_PREFIX "[%u] %s ( ", timestamp, dbglog_get_msg(mod_id, dbg_id));
        } else {
            snprintf(buf, sizeof(buf), DBGLOG_PRINT_PREFIX "[%u] %s ( ", timestamp, dbglog_get_msg(mod_id, dbg_id));
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
    }

    for (i = 0; i < numargs; i++) {
#if USE_NUMERIC
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%u", args[i]);
        } else {
            snprintf(buf, sizeof(buf), "%u", args[i]);
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
#else
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%#x", args[i]);
        } else {
            snprintf(buf, sizeof(buf), "%#x", args[i]);
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
#endif
        if ((i + 1) < numargs) {
            if (dbglog_prt_path == DBGLOG_PRT_WMI) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, ", ");
            } else {
                snprintf(buf, sizeof(buf), ", ");
#ifndef REMOVE_PKT_LOG
                if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
                }
#endif
            }
        }
    }

    if (dbglog_prt_path == DBGLOG_PRT_WMI) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " )\n");
    } else {
        snprintf(buf, sizeof(buf), " )\n");
#ifndef REMOVE_PKT_LOG
        if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
        }
#endif
    }

    return TRUE;
}

int
dbglog_parse_debug_logs(ol_scn_t scn, u_int8_t *datap, u_int16_t len, void *context)
{
    A_UINT32 count;
    A_UINT32 *buffer;
    A_UINT32 timestamp;
    A_UINT32 debugid;
    A_UINT32 moduleid;
    A_UINT16 vapid;
    A_UINT16 numargs;
    A_UINT16 length;
    A_UINT32 dropped;
    char buf[512];

#if OL_ATH_SMART_LOGGING
    smart_log_mem_t *smart_log_file = NULL;

    if (scn->sc_ic.smart_logging == 1) {
        smart_log_file = (smart_log_mem_t *) scn->sc_ic.smart_log_file;
    }
#endif /* OL_ATH_SMART_LOGGING */
    dbglog_prt_path = (dbglog_prt_path_t) context;
    dropped = *((A_UINT32 *)datap);
    datap += sizeof(dropped);
    len -= sizeof(dropped);
    if (dropped > 0) {
        if (dbglog_prt_path == DBGLOG_PRT_WMI) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, DBGLOG_PRINT_PREFIX "%d log buffers are dropped \n",
                                                                dropped);
        } else {
            snprintf(buf, sizeof(buf), DBGLOG_PRINT_PREFIX "%d log buffers are dropped \n",
                                                                    dropped);
#ifndef REMOVE_PKT_LOG
            if (strlcat(dbglog_print_buffer, buf, sizeof(dbglog_print_buffer)) >= sizeof(dbglog_print_buffer)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Truncated buffer dest buff[%s][%d] and source buff[%s][%d]\n", dbglog_print_buffer, strlen(dbglog_print_buffer), buf, strlen(buf));
            }
#endif
        }
    }

    count = 0;
    buffer = (A_UINT32 *)datap;
    length = (len >> 2);

#if OL_ATH_SMART_LOGGING
    if (scn->sc_ic.smart_logging == 1) {
        store_smart_debug_log(smart_log_file, SMART_LOG_TYPE_FW, datap, len);
    }
#endif /* OL_ATH_SMART_LOGGING */

    while (count < length) {
        debugid = DBGLOG_GET_DBGID(buffer[count + 1]);
        moduleid = DBGLOG_GET_MODULEID(buffer[count + 1]);
        vapid = DBGLOG_GET_VAPID(buffer[count + 1]);
        numargs = DBGLOG_GET_NUMARGS(buffer[count + 1]);
        timestamp = DBGLOG_GET_TIME_STAMP(buffer[count]);

        if (moduleid >= WLAN_MODULE_ID_MAX)
            return 0;
       /* this will append devname [wifiX] before [FWLOG] Message to differentiate radios */
        if( dbglog_ratelimit_print()) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "[%s] ", scn->sc_osdev->netdev->name);
        }
        if (mod_print[moduleid] == NULL) {
            /* No module specific log registered use the default handler*/
            dbglog_default_print_handler(moduleid, vapid, debugid, timestamp,
                                         numargs,
                                         (((A_UINT32 *)buffer) + 2 + count));
        } else {
            if(!(mod_print[moduleid](moduleid, vapid, debugid, timestamp,
                            numargs,
                            (((A_UINT32 *)buffer) + 2 + count)))) {
                /* The message is not handled by the module specific handler*/
                dbglog_default_print_handler(moduleid, vapid, debugid, timestamp,
                        numargs,
                        (((A_UINT32 *)buffer) + 2 + count));

            }
        }

        count += numargs + 2; /* 32 bit Time stamp + 32 bit Dbg header*/
    }
    /* Always returns zero */
    return (0);
}

void
dbglog_reg_modprint(A_UINT32 mod_id, module_dbg_print printfn)
{
    if (!mod_print[mod_id]) {
        mod_print[mod_id] = printfn;
    } else {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "module print is already registered for thsi module %d\n",
               mod_id);
    }
}

void
dbglog_sm_print(
        A_UINT32 timestamp,
        A_UINT16 vap_id,
        A_UINT16 numargs,
        A_UINT32 *args,
        const char *module_prefix,
        const char *states[], A_UINT32 num_states,
        const char *events[], A_UINT32 num_events)
{
    A_UINT8 type, arg1, arg2, arg3;
    A_UINT32 extra;

    if (numargs != 2) {
        return;
    }

    type = (args[0] >> 24) & 0xff;
    arg1 = (args[0] >> 16) & 0xff;
    arg2 = (args[0] >>  8) & 0xff;
    arg3 = (args[0] >>  0) & 0xff;

    extra = args[1];

    switch (type) {
    case 0: /* state transition */
        if (arg1 < num_states && arg2 < num_states) {
            dbglog_printf(timestamp, vap_id, "%s: %s => %s (%#x)",
                    module_prefix, states[arg1], states[arg2], extra);
        } else {
            dbglog_printf(timestamp, vap_id, "%s: %u => %u (%#x)",
                    module_prefix, arg1, arg2, extra);
        }
        break;
    case 1: /* dispatch event */
        if (arg1 < num_states && arg2 < num_events) {
            dbglog_printf(timestamp, vap_id, "%s: %s < %s (%#x)",
                    module_prefix, states[arg1], events[arg2], extra);
        } else {
            dbglog_printf(timestamp, vap_id, "%s: %u < %u (%#x)",
                    module_prefix, arg1, arg2, extra);
        }
        break;
    case 2: /* warning */
        switch (arg1) {
        case 0: /* unhandled event */
            if (arg2 < num_states && arg3 < num_events) {
                dbglog_printf(timestamp, vap_id, "%s: unhandled event %s in state %s (%#x)",
                        module_prefix, events[arg3], states[arg2], extra);
            } else {
                dbglog_printf(timestamp, vap_id, "%s: unhandled event %u in state %u (%#x)",
                        module_prefix, arg3, arg2, extra);
            }
            break;
        default:
            break;

        }
        break;
    }
}

A_BOOL
dbglog_sta_powersave_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
    static const char *states[] = {
        "IDLE",
        "ACTIVE",
        "SLEEP_TXQ_FLUSH",
        "SLEEP_TX_SENT",
        "PAUSE",
        "SLEEP_DOZE",
        "SLEEP_AWAKE",
        "ACTIVE_TXQ_FLUSH",
        "ACTIVE_TX_SENT",
        "PAUSE_TXQ_FLUSH",
        "PAUSE_TX_SENT",
        "IDLE_TXQ_FLUSH",
        "IDLE_TX_SENT",
    };

    static const char *events[] = {
        "START",
        "STOP",
        "PAUSE",
        "UNPAUSE",
        "TIM",
        "DTIM",
        "SEND_COMPLETE",
        "PRE_SEND",
        "RX",
        "HWQ_EMPTY",
        "PAUSE_TIMEOUT",
        "TXRX_INACTIVITY_TIMEOUT",
        "PSPOLL_TIMEOUT",
        "UAPSD_TIMEOUT",
        "DELAYED_SLEEP_TIMEOUT",
        "SEND_N_COMPLETE",
        "TIDQ_PAUSE_COMPLETE",
    };

    switch (dbg_id) {
    case DBGLOG_DBGID_SM_FRAMEWORK_PROXY_DBGLOG_MSG:
        dbglog_sm_print(timestamp, vap_id, numargs, args, "STA PS",
                states, ARRAY_LENGTH(states), events, ARRAY_LENGTH(events));
        break;
    case PS_STA_PM_ARB_REQUEST:
        if (numargs == 4) {
            dbglog_printf(timestamp, vap_id, "PM ARB request flags=%x, last_time=%x %s: %s",
                    args[1], args[2], dbglog_get_module_str[args[0]], args[3] ? "SLEEP" : "WAKE");
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case PS_STA_DELIVER_EVENT:
        if (numargs == 2) {
            dbglog_printf(timestamp, vap_id, "STA PS: %s %u",
                    (args[0] == 0 ? "PAUSE_COMPLETE" :
                    (args[0] == 1 ? "UNPAUSE_COMPLETE" :
                    (args[0] == 2 ? "SLEEP" :
                    (args[0] == 3 ? "AWAKE" : "UNKNOWN")))),
                    args[1]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

A_BOOL dbglog_ratectrl_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
    switch (dbg_id) {
        case RATECTRL_DBGID_ASSOC:
           {
           A_UINT8 chainmask = args[0] >> 24;
           A_UINT8 peer_mac_nib1 = ((args[0] >>8) & 0x000000FF);
           A_UINT8 peer_mac_nib2 = args[0] & 0x000000FF;
           A_UINT16 vht_mcs_set = args[3] & 0xFFFF;
           A_UINT16 legacy_rate_set = args[3] >> 16;

           dbglog_printf(timestamp, vap_id, "RATE: ChainMask %x, peer_mac %x:%x, phymode %d, ni_flags 0x%08x, vht_mcs_set 0x%04x, ht_mcs_set 0x%04x, legacy_rate_set 0x%04x",
              chainmask, peer_mac_nib1, peer_mac_nib2, args[1], args[2], vht_mcs_set, args[4], legacy_rate_set);
	   }
           break;
        case RATECTRL_DBGID_NSS_CHANGE:
           dbglog_printf(timestamp, vap_id, "RATE: NEW NSS %d\n", args[0]);
           break;
        case RATECTRL_DBGID_CHAINMASK_ERR:
           dbglog_printf(timestamp, vap_id, "RATE: Chainmask ERR %d %d %d\n",
               args[0], args[1], args[2]);
           break;
        case RATECTRL_DBGID_UNEXPECTED_FRAME:
           dbglog_printf(timestamp, vap_id, "RATE: WARN1: rate %d flags 0x%08x\n", args[0], args[1]);
           break;
        case RATECTRL_DBGID_WAL_RCQUERY:
            dbglog_printf(timestamp, vap_id, "ratectrl_dbgid_wal_rcquery [rix1 %d rix2 %d rix3 %d proberix %d ppduflag 0x%x] ",
                    args[0], args[1], args[2], args[3], args[4]);
            break;
        case RATECTRL_DBGID_WAL_RCUPDATE:
            dbglog_printf(timestamp, vap_id, "ratectrl_dbgid_wal_rcupdate [numelems %d ppduflag 0x%x] ",
                    args[0], args[1]);
    }
    return TRUE;
}

A_BOOL dbglog_dcs_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
  switch (dbg_id) {
   case WLAN_DCS_DBGID_INIT:
        dbglog_printf(timestamp, vap_id,
        "DCS init:  %d", args[0]);
        break;
   case WLAN_DCS_DBGID_WMI_CWINT:
        dbglog_printf(timestamp, vap_id,
        "DCS wmi cwinit:  %d", args[0]);
        break;
   case WLAN_DCS_DBGID_TIMER:
        dbglog_printf(timestamp, vap_id,
        "DCS timer:  %d", args[0]);
        break;
   case WLAN_DCS_DBGID_CMDG:
        dbglog_printf(timestamp, vap_id,
        "DCS cmdg:  %d", args[0]);
        break;
   case WLAN_DCS_DBGID_CMDS:
        dbglog_printf(timestamp, vap_id,
        "DCS cmds:  %d", args[0]);
        break;
   case WLAN_DCS_DBGID_DINIT:
        dbglog_printf(timestamp, vap_id,
        "DCS dinit:  %d", args[0]);
        break;
   default:
        dbglog_printf(timestamp, vap_id,
        "DCS arg %d", args[0]);
        break;
  }
    return TRUE;
}

A_BOOL dbglog_rtt_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
    switch (dbg_id) {
    case RTT_CALL_FLOW:
        {
            char const * call_flow_str = "UNKNOWN - update your RTT call flow strings and recompile the host";
            if (args[0] < RTT_CALL_FLOW_MSG_MAX) {
                call_flow_str = RTT_CALL_FLOW_MSG[args[0]];
            }
            dbglog_printf(timestamp, vap_id, "RTT_CALL_FLOW: (%08x [%04x]) %02d - %s",
                    args[1],
                    (A_UINT32)((A_UINT16) (args[1] >> 10)),
                    args[0],
                    (char *) call_flow_str);
        }
        return TRUE;
    case RTT_ERROR_REPORT:
        {
            if (args[0] < RTT_ERR_MSG_MAX) {
                dbglog_printf(timestamp, vap_id, "RTT_ERROR_REPORT: %02d - %s", args[0], (char *) RTT_ERR_MSG[args[0]]);
                return TRUE;
            }
        }
        // If we don't know the error string, use the default print function
        return FALSE;
    case RTT_FTM_PARAM_INFO:
        {
            A_UINT16 source = (A_UINT16) args[0] & 0x00000001;
            char const * source_str = source ? "RESPONDER" : "INITIATOR";

            A_UINT32 num_burst_exp = (args[1] & 0xF);
            A_UINT32 min_delta_ftm = ((args[1] >> 8 ) & 0x000000FF);
            A_UINT32 ftm_format_and_bandwidth = ((args[0] >> 24) & 0x000000FF);
            A_UINT32 burst_duration = args[2] & 0x0000000F;

            A_UINT32 status = (args[0] >> 4)  & 0x000000003;
            A_UINT32 value =  (args[0] >> 8)  & 0x0000000FF;

            dbglog_printf(timestamp, vap_id, "RTT_FTM_PARAM_INFO:");
            dbglog_printf(timestamp, vap_id, "  Source:         %s", source_str);
            dbglog_printf(timestamp, vap_id, "  ASAP Capable:   %d", ((args[0] >> 16) & 0x00000001));
            dbglog_printf(timestamp, vap_id, "  ASAP:           %d", ((args[0] >> 17) & 0x00000001));
            dbglog_printf(timestamp, vap_id, "  Format & BW:    %d (%s)",
                    ftm_format_and_bandwidth,
                    dbglog_rtt_get_format_and_bandwidth_str(ftm_format_and_bandwidth));

            dbglog_printf(timestamp, vap_id, "  Num Burst Exp:  %d (%d bursts)", num_burst_exp, (1 << num_burst_exp));
            dbglog_printf(timestamp, vap_id, "  Min Delta FTM:  %d (%d us)", min_delta_ftm, (min_delta_ftm * 100));
            dbglog_printf(timestamp, vap_id, "  FTM Per Burst:  %d", ((args[1] >> 16) & 0x0000FFFF));

            dbglog_printf(timestamp, vap_id, "  Burst Duration: %d (%s)",
                    burst_duration,
                    dbglog_rtt_get_burst_duration_str(burst_duration));

            dbglog_printf(timestamp, vap_id, "  Partial TSF:    %d (0x%04x)", args[3], args[3]);
            dbglog_printf(timestamp, vap_id, "  Burst Period:   %d (%d ms)", args[4], (args[4] * 100));
            dbglog_printf(timestamp, vap_id, "  Status:         %d (%s)", status, RTT_FTM_PARAM_STATUS_STR[status]);
            dbglog_printf(timestamp, vap_id, "  Value:          %d (0x%02x)", value, value);
        }
        return TRUE;
    default:
        break;
    }

    return FALSE;
}


A_BOOL dbglog_ani_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
  switch (dbg_id) {
   case ANI_DBGID_ENABLE:
        dbglog_printf(timestamp, vap_id,
        "ANI Enable:  %d", args[0]);
        break;
   case ANI_DBGID_POLL:
        dbglog_printf(timestamp, vap_id,
        "ANI POLLING: AccumListenTime %d ListenTime %d ofdmphyerr %d cckphyerr %d",
                args[0], args[1], args[2],args[3]);
        break;
   case ANI_DBGID_CURRENT_LEVEL:
        dbglog_printf(timestamp, vap_id,
        "ANI CURRENT LEVEL: ofdm level %d cck level %d",
                args[0], args[1]);
        break;

   case ANI_DBGID_RESTART:
        dbglog_printf(timestamp, vap_id,
        "ANI RESTART: AccumListenTime %d ListenTime %d ofdmphyerr %d cckphyerr %d",
                args[0], args[1], args[2],args[3]);
        break;
   case ANI_DBGID_OFDM_LEVEL:
        dbglog_printf(timestamp, vap_id,
        "ANI UPDATE ofdm level %d firstep %d firstep_low %d cycpwr_thr %d self_corr_low %d",
        args[0], args[1],args[2],args[3],args[4]);
        break;
   case ANI_DBGID_CCK_LEVEL:
        dbglog_printf(timestamp, vap_id,
                "ANI UPDATE  cck level %d firstep %d firstep_low %d mrc_cck %d",
                args[0],args[1],args[2],args[3]);
        break;
   case ANI_DBGID_CONTROL:
        dbglog_printf(timestamp, vap_id,
                "ANI CONTROL ofdmlevel %d ccklevel %d\n",
                args[0]);
        break;
   case ANI_DBGID_OFDM_PARAMS:
        dbglog_printf(timestamp, vap_id,
                "ANI ofdm_control firstep %d cycpwr %d\n",
                args[0],args[1]);
        break;
   case ANI_DBGID_CCK_PARAMS:
        dbglog_printf(timestamp, vap_id,
                "ANI cck_control mrc_cck %d barker_threshold %d\n",
                args[0],args[1]);
        break;
   case ANI_DBGID_RESET:
        dbglog_printf(timestamp, vap_id,
                "ANI resetting resetflag %d resetCause %8x channel index %d",
                args[0],args[1],args[2]);
        break;
   case ANI_DBGID_SELF_CORR_LOW:
        dbglog_printf(timestamp, vap_id,"ANI self_corr_low %d",args[0]);
        break;
   case ANI_DBGID_FIRSTEP:
        dbglog_printf(timestamp, vap_id,"ANI firstep %d firstep_low %d",
            args[0],args[1]);
        break;
   case ANI_DBGID_MRC_CCK:
        dbglog_printf(timestamp, vap_id,"ANI mrc_cck %d",args[0]);
        break;
   case ANI_DBGID_CYCPWR:
        dbglog_printf(timestamp, vap_id,"ANI cypwr_thresh %d",args[0]);
        break;
   case ANI_DBGID_POLL_PERIOD:
        dbglog_printf(timestamp, vap_id,"ANI Configure poll period to %d",args[0]);
        break;
   case ANI_DBGID_LISTEN_PERIOD:
        dbglog_printf(timestamp, vap_id,"ANI Configure listen period to %d",args[0]);
        break;

   case ANI_DBGID_OFDM_LEVEL_CFG:
        dbglog_printf(timestamp, vap_id,"ANI Configure ofdm level to %d",args[0]);
        break;

   case ANI_DBGID_CCK_LEVEL_CFG:
        dbglog_printf(timestamp, vap_id,"ANI Configure cck level to %d",args[0]);
        break;

   default:
        dbglog_printf(timestamp, vap_id,"ANI arg1 %d arg2 %d arg3 %d",
              args[0],args[1],args[2]);
        break;
  }
    return TRUE;
}

A_BOOL
dbglog_ap_powersave_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
    switch (dbg_id) {
    case AP_PS_DBGID_UPDATE_TIM:
        if (numargs == 2) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: TIM update AID=%u %s",
                    args[0], args[1] ? "set" : "clear");
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_PEER_STATE_CHANGE:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u power save %s peer_mac = 0x%02x",
                    args[0], args[1] ? "enabled" : "disabled",args[2]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_PSPOLL:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u pspoll response tid=%u flags=%x",
                    args[0], args[2], args[3]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_PEER_CREATE:
        if (numargs == 1) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: create peer AID=%u", args[0]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_PEER_DELETE:
        if (numargs == 1) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: delete peer AID=%u", args[0]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_VDEV_CREATE:
        dbglog_printf(timestamp, vap_id, "AP PS: vdev create");
        break;
    case AP_PS_DBGID_VDEV_DELETE:
        dbglog_printf(timestamp, vap_id, "AP PS: vdev delete");
        break;
    case AP_PS_DBGID_SYNC_TIM:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u advertised=%#x buffered=%#x", args[0], args[1], args[2]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_NEXT_RESPONSE:
        if (numargs == 4) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u select next response %s%s%s", args[0],
                    args[1] ? "(usp active) " : "",
                    args[2] ? "(pending usp) " : "",
                    args[3] ? "(pending poll response)" : "");
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_START_SP:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u START SP tsf=%#x (%u)",
                    args[0], args[1], args[2]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_COMPLETED_EOSP:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u EOSP eosp_tsf=%#x trigger_tsf=%#x",
                    args[0], args[1], args[2]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_TRIGGER:
        if (numargs == 4) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u TRIGGER tsf=%#x %s%s", args[0], args[1],
                    args[2] ? "(usp active) " : "",
                    args[3] ? "(send_n in progress)" : "");
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_DUPLICATE_TRIGGER:
        if (numargs == 4) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u DUP TRIGGER tsf=%#x seq=%u ac=%u",
                    args[0], args[1], args[2], args[3]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_UAPSD_RESPONSE:
        if (numargs == 5) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u UAPSD response tid=%u, n_mpdu=%u flags=%#x max_sp=%u current_sp=%u",
                    args[0], args[1], args[2], args[3], (args[4] >> 16) & 0xffff, args[4] & 0xffff);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_SEND_COMPLETE:
        if (numargs == 5) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u SEND_COMPLETE fc=%#x qos=%#x %s%s",
                    args[0], args[1], args[2],
                    args[3] ? "(usp active) " : "",
                    args[4] ? "(pending poll response)" : "");
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_SEND_N_COMPLETE:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u SEND_N_COMPLETE %s%s",
                    args[0],
                    args[1] ? "(usp active) " : "",
                    args[2] ? "(pending poll response)" : "");
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case AP_PS_DBGID_DETECT_OUT_OF_SYNC_STA:
        if (numargs == 4) {
            dbglog_printf(timestamp, vap_id,
                    "AP PS: AID=%u detected out-of-sync now=%u tx_waiting=%u txq_depth=%u",
                   args[0], args[1], args[2], args[3]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

A_BOOL
dbglog_wal_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
    static const char *states[] = {
        "ACTIVE",
        "WAIT",
        "WAIT_FILTER",
        "PAUSE",
        "PAUSE_SEND_N",
        "BLOCK",
    };

    static const char *events[] = {
        "PAUSE",
        "PAUSE_FILTER",
        "UNPAUSE",

        "BLOCK",
        "BLOCK_FILTER",
        "UNBLOCK",

        "HWQ_EMPTY",
        "ALLOW_N",
    };

#define WAL_VDEV_TYPE(type)     \
    (type == 0 ? "AP" :       \
    (type == 1 ? "STA" :        \
    (type == 2 ? "IBSS" :         \
    (type == 2 ? "MONITOR" :    \
     "UNKNOWN"))))

#define WAL_SLEEP_STATE(state)      \
    (state == 1 ? "NETWORK SLEEP" : \
    (state == 2 ? "AWAKE" :         \
    (state == 3 ? "SYSTEM SLEEP" :  \
    "UNKNOWN")))

    switch (dbg_id) {
    case DBGLOG_DBGID_SM_FRAMEWORK_PROXY_DBGLOG_MSG:
        dbglog_sm_print(timestamp, vap_id, numargs, args, "TID PAUSE",
                states, ARRAY_LENGTH(states), events, ARRAY_LENGTH(events));
        break;
    case WAL_DBGID_SET_POWER_STATE:
        if (numargs == 3) {
            dbglog_printf(timestamp, vap_id,
                    "WAL %s => %s, req_count=%u",
                    WAL_SLEEP_STATE(args[0]), WAL_SLEEP_STATE(args[1]),
                    args[2]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case WAL_DBGID_CHANNEL_CHANGE_FORCE_RESET:
        if (numargs == 4) {
            dbglog_printf(timestamp, vap_id,
                    "WAL channel change (force reset) freq=%u, mode=%u flags=%u rx_ok=%u tx_ok=%u",
                    args[0] & 0x0000ffff, (args[0] & 0xffff0000) >> 16, args[1],
                    args[2], args[3]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case WAL_DBGID_CHANNEL_CHANGE:
        if (numargs == 2) {
            dbglog_printf(timestamp, vap_id,
                    "WAL channel change freq=%u, mode=%u flags=%u rx_ok=1 tx_ok=1",
                    args[0] & 0x0000ffff, (args[0] & 0xffff0000) >> 16, args[1]);
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case WAL_DBGID_VDEV_START:
        if (numargs == 1) {
            dbglog_printf(timestamp, vap_id, "WAL %s vdev started",
                    WAL_VDEV_TYPE(args[0]));
        } else {
            dbglog_num_args_err(mod_id, vap_id, dbg_id, numargs);
        }
        break;
    case WAL_DBGID_VDEV_STOP:
        dbglog_printf(timestamp, vap_id, "WAL %s vdev stopped",
                WAL_VDEV_TYPE(args[0]));
        break;
    case WAL_DBGID_VDEV_UP:
        dbglog_printf(timestamp, vap_id, "WAL %s vdev up, count=%u",
                WAL_VDEV_TYPE(args[0]), args[1]);
        break;
    case WAL_DBGID_VDEV_DOWN:
        dbglog_printf(timestamp, vap_id, "WAL %s vdev down, count=%u",
                WAL_VDEV_TYPE(args[0]), args[1]);
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

A_BOOL
dbglog_scan_print_handler(
        A_UINT32 mod_id,
        A_UINT16 vap_id,
        A_UINT32 dbg_id,
        A_UINT32 timestamp,
        A_UINT16 numargs,
        A_UINT32 *args)
{
    static const char *states[] = {
        "IDLE",
        "BSSCHAN",
        "WAIT_FOREIGN_CHAN",
        "FOREIGN_CHANNEL",
        "TERMINATING"
    };

    static const char *events[] = {
        "REQ",
        "STOP",
        "BSSCHAN",
        "FOREIGN_CHAN",
        "CHECK_ACTIVITY",
        "REST_TIME_EXPIRE",
        "DWELL_TIME_EXPIRE",
        "PROBE_TIME_EXPIRE",
    };

    switch (dbg_id) {
    case DBGLOG_DBGID_SM_FRAMEWORK_PROXY_DBGLOG_MSG:
        dbglog_sm_print(timestamp, vap_id, numargs, args, "SCAN",
                states, ARRAY_LENGTH(states), events, ARRAY_LENGTH(events));
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

void
dbglog_init(void *sc)
{
    struct ol_ath_softc_net80211 *scn = sc;

    OS_MEMSET(mod_print, 0, sizeof(mod_print));

    dbglog_reg_modprint(WLAN_MODULE_STA_PWRSAVE, dbglog_sta_powersave_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_AP_PWRSAVE, dbglog_ap_powersave_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_WAL, dbglog_wal_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_SCAN, dbglog_scan_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_RATECTRL, dbglog_ratectrl_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_ANI,dbglog_ani_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_DCS,dbglog_dcs_print_handler);
    dbglog_reg_modprint(WLAN_MODULE_RTT,dbglog_rtt_print_handler);

#if DBGLOG_WQ_BASED
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_dbg_msg_event_id,
                        dbglog_message_handler, WMI_RX_WORK_CTX);
#else
    wmi_unified_register_event_handler(scn->wmi_handle, wmi_dbg_msg_event_id,
                        dbglog_message_handler, WMI_RX_UMAC_CTX);
#endif
}

#define DBGLOG_MAX_EVT_QUEUE 100
int
dbglog_message_handler(ol_scn_t sc, uint8_t *evt_b, uint16_t len)
{
    struct ol_ath_softc_net80211 *scn = sc;
    u_int8_t *data;

    data = wmi_extract_dbglog_data_len(scn->wmi_handle, evt_b, &len);

    if (!data)
	return -1;

    dbglog_parse_debug_logs(sc, data, len, DBGLOG_PRT_WMI);

    return 0;
}

void dbglog_free(void *sc)
{
    return;
}

#ifdef unittest_dbglogs

void
test_dbg_config(ol_scn_t scn)
{
    dbglog_module_log_enable(scn, 4, 0);
    dbglog_vap_log_enable(scn, 15, 0);
    dbglog_set_log_lvl(scn, 1);
}
#endif /* unittest_dbglogs */

void
dbglog_ratelimit_set(A_UINT32 burst_limit)
{
#if DBGLOG_WQ_BASED
    dbglog_ratelimit.burst = burst_limit;
#endif
}

#if OL_ATH_SMART_LOGGING
/* Handler for the Smartlogging wmi events.It performs the corresponding
 * action according to the event received. All the events stored in the
 * smartlog storage file */
int
debug_fatal_condition_handler(ol_scn_t sc, A_UINT8 *evt_b, A_UINT16 len)
{
    struct ol_ath_softc_net80211 *scn = sc;
    struct wmi_debug_fatal_events_t events;
    A_UINT8 *data;
    A_UINT32 ev = 0;
    smart_log_mem_t *smart_log_file = NULL;
    A_UINT32 smart_log_skb_sz = 0;

    if (scn->sc_ic.smart_logging == 0) {
        return 0;
    }

    smart_log_file = (smart_log_mem_t *) scn->sc_ic.smart_log_file;
    smart_log_skb_sz = scn->sc_ic.smart_log_skb_sz;

    if (wmi_extract_smartlog_ev(scn->wmi_handle, evt_b, &events) != EOK)
        return -1;

    for(ev = 0; ev < events.num_events ; ev++) {

        data =(uint8_t *) &events.event[ev];
        switch(events.event[ev].type) {

            case WMI_FATAL_CONDITION_EVENT_COMPLETION:
                qdf_print("SmartLogEvent: FATAL COMPLETION EVENT\n");
                store_smart_debug_log(smart_log_file, SMART_LOG_TYPE_EVENT, data,
                                       sizeof(struct wmi_fatal_condition_event));
                break;

            case WMI_FATAL_CONDITION_CE_FAILURE:
            {
                struct hif_opaque_softc *hif_hdl = (struct hif_opaque_softc *)(scn->hif_hdl);
                struct hif_softc *hif_scn = HIF_GET_SOFTC(hif_hdl);

                qdf_print("SmartLogEvent: CE FAILURE EVENT\n");
                if ((SMART_LOG_MEM - (smart_log_file->cur - smart_log_file->start)) < 4 + SMART_LOG_RING_GAURD) {
                    smart_log_file->cur = smart_log_file->start;
                }
                /* Dump only the CE5 target->Host CE for now as FW detects only issues in CE5 */
                smart_log_file->cur += qdf_snprint(smart_log_file->cur, 4,
                                                "CE%d", 5);
                smart_log_file->cur = hif_log_dump_ce(hif_scn,
                                                     smart_log_file->cur,
                                                     smart_log_file->start,
                                     SMART_LOG_MEM - SMART_LOG_RING_GAURD,
                                                    5, smart_log_skb_sz);
            }
            break;

            case WMI_FATAL_CONDITION_TIMEOUTS:
                switch(events.event[ev].subtype)
                {
                    case WMI_FATAL_SUBTYPE_TX_TIMEOUT:
                        qdf_print("SmartLogEvent: TX TIMEOUT SUBEVENT\n");
                        store_smart_debug_log(smart_log_file, SMART_LOG_TYPE_EVENT, data,
                                              sizeof(struct wmi_fatal_condition_event));
                        break;
                    case WMI_FATAL_SUBTYPE_RX_TIMEOUT:
                        qdf_print("SmartLogEvent: RX TIMEOUT SUBEVENT\n");
                        store_smart_debug_log(smart_log_file, SMART_LOG_TYPE_EVENT, data,
                                              sizeof(struct wmi_fatal_condition_event));

                        break;
                }
                break;

            case WMI_FATAL_CONDITION_CONNECTION_ISSUE:
                switch(events.event[ev].subtype)
                {
                    case WMI_FATAL_SUBTYPE_STA_KICKOUT:
                        qdf_print("SmartLogEvent: STA KICKOUT SUBEVENT\n");
                        store_smart_debug_log(smart_log_file, SMART_LOG_TYPE_EVENT, data,
                                              sizeof(struct wmi_fatal_condition_event));
                        break;
                }
                break;
        }
    }
    return 0;
}

int
smart_log_init(void *sc)
{
    struct ol_ath_softc_net80211 *scn = sc;
    struct ieee80211com *ic = &(scn->sc_ic);

    smart_log_mem_t *smart_log_file;

    if ((smart_log_file = qdf_mem_malloc(sizeof(*smart_log_file))) == NULL) {
        qdf_print("Memory allocation of smartlog failed\n");
        return -1;
    }

    ic->smart_log_file = smart_log_file;

#if DBGLOG_WQ_BASED
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_debug_fatal_condition_eventid,
                                                debug_fatal_condition_handler, WMI_RX_WORK_CTX);
#else
        wmi_unified_register_event_handler(scn->wmi_handle, wmi_debug_fatal_condition_eventid,
                                                debug_fatal_condition_handler, WMI_RX_UMAC_CTX);
#endif

    if ((smart_log_file->start = (A_UINT8*) qdf_mem_malloc(SMART_LOG_MEM)) ==  NULL)
    {
        qdf_print("Memory allocation of smartlog failed\n");
        qdf_mem_free(smart_log_file);
        return -1;
    }

    OS_MEMSET(smart_log_file->start, 0, SMART_LOG_MEM);
    smart_log_file->cur = smart_log_file->start;
    smart_log_file->dbgfs.blob.data = smart_log_file->start;
    smart_log_file->dbgfs.blob.size = SMART_LOG_MEM;

    qdf_snprint(smart_log_file->dbgfs.name, SMARTLOG_DBGFS_NAME, "smart_log_dump%d", ic->interface_id);
    smart_log_file->dbgfs.dfs = debugfs_create_blob(smart_log_file->dbgfs.name, S_IRUSR, NULL,
                             &smart_log_file->dbgfs.blob);
    ic->smart_logging = 1;

    qdf_print("%s: Smart logging Enabled buf=%p (size=%lu)\n", __func__, smart_log_file->start, SMART_LOG_MEM);

    return 0;

}

void  store_smart_debug_log(smart_log_mem_t *file, SMARTLOG_TYPE type, A_UINT8 *data, A_UINT32 len)
{
    if ((file == NULL) || (data == NULL)) {
        return;
    }

    if ((SMART_LOG_MEM - (file->cur - file->start)) < (len + 4 + SMART_LOG_RING_GAURD)) {
        file->cur = file->start;
    }

    if (type == SMART_LOG_TYPE_FW) {
        file->cur += qdf_snprint(file->cur, 4, "FWL");
        OS_MEMCPY(file->cur, data, len);
        file->cur += len;
    }
    else if (type == SMART_LOG_TYPE_EVENT) {

        file->cur += qdf_snprint(file->cur, 4, "EVT");
        OS_MEMCPY(file->cur, data, len);
        file->cur += len;
    }
}

ssize_t smart_logs_dump(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct net_device *net = to_net_dev(dev);
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(net);
    struct ieee80211com *ic = &scn->sc_ic;
    smart_log_mem_t *smart_log_file = NULL;

    if (ic->smart_logging == 0) {
        qdf_print("Smart logging not enabled\n");
        return 0;
    }

    smart_log_file = ic->smart_log_file;
    if (smart_log_file != NULL) {
        print_hex_dump(KERN_ERR, " ", DUMP_PREFIX_ADDRESS, 16, 1,
               smart_log_file->start, SMART_LOG_MEM, true);
    }

    return 0;
}

void
smart_log_deinit(void *sc)
{
    struct ol_ath_softc_net80211 *scn = sc;
    struct ieee80211com *ic = &(scn->sc_ic);
    smart_log_mem_t *smart_log_file;

    smart_log_file = ic->smart_log_file;

    wmi_unified_unregister_event_handler(scn->wmi_handle, wmi_debug_fatal_condition_eventid);

    debugfs_remove(smart_log_file->dbgfs.dfs);

    qdf_mem_free(smart_log_file->start);
    qdf_mem_free(ic->smart_log_file);
    ic->smart_log_file = NULL;
    ic->smart_logging = 0;

    qdf_print("%s: Smart logging Disabled\n", __func__);
}
#endif /* OL_ATH_SMART_LOGGING */
