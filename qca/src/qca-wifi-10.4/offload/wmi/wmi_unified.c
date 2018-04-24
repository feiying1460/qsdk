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
 * Host WMI unified implementation
 */

#include "athdefs.h"
#include "a_types.h"
#include "a_osapi.h"
#include "a_debug.h"
#include "ol_if_ath_api.h"
#include "ol_helper.h"
#include "htc_api.h"
#include "dbglog_host.h"
#include "wmi.h"
#include "wmi_unified_priv.h"
#include "htt.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <fs/proc/internal.h>
#else
#include <linux/proc_fs.h>
#endif

#ifdef ATHR_WIN_NWF
#define ATH_MODULE_NAME wmi
#ifdef DEBUG
#define ATH_DEBUG_WMI  ATH_DEBUG_MAKE_MODULE_MASK(0)
static ATH_DEBUG_MASK_DESCRIPTION wmi_debug_desc[] = {
    { ATH_DEBUG_WMI , "WMI Tracing"},
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(wmi,
                                 "wmi",
                                 "Wireless Module Interface",
                                 ATH_DEBUG_MASK_DEFAULTS,
                                 ATH_DEBUG_DESCRIPTION_COUNT(wmi_debug_desc),
                                 wmi_debug_desc);

#endif
#endif

#if ATH_PERF_PWR_OFFLOAD


/* WMI buffer APIs */

wmi_buf_t
wmi_buf_alloc(wmi_unified_t wmi_handle, int len)
{
    wmi_buf_t wmi_buf;
    /* NOTE: For now the wbuf type is used as WBUF_TX_CTL
     * But this need to be changed appropriately to reserve
     * proper headroom for wmi_buffers
     */
    wmi_buf = wbuf_alloc(wmi_handle->osdev, WBUF_TX_CTL, len);
    if( NULL == wmi_buf )
    {
        /* wbuf_alloc returns NULL if the internel pool in wmi_handle->osdev
         * is empty
         */
        return NULL;
    }


    /* Clear the wmi buffer */
    OS_MEMZERO(wbuf_header(wmi_buf), len);

    /*
     * Set the length of the buffer to match the allocation size.
     */
    wbuf_set_pktlen(wmi_buf, len);
    return wmi_buf;
}

#define htt_host_data_dl_len(_osbuf)  (HTC_HDR_ALIGNMENT_PADDING + HTT_SW_MSDU_DESC_LEN + HTT_SDU_HDR_LEN)

/*
 * Flush the HTC endpoint associated with WMI
 */
void
wmi_flush_endpoint(wmi_unified_t wmi_handle){

    htc_flush_endpoint(wmi_handle->htc_handle, wmi_handle->wmi_endpoint_id, 0);

}

/* WMI API to block the WMI command  */
int
wmi_stop(wmi_unified_t wmi_handle) {
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WMI Stop \n");
    wmi_handle->wmi_stopinprogress = 1;
    return 0;
}

#if WMI_RECORDING
void wmi_add_to_circ(wmi_unified_t h, char *cmd, int len, WMI_CMD_ID id);
#endif


/* WMI command API */
int
wmi_unified_cmd_send(wmi_unified_t wmi_handle, wmi_buf_t buf, int len, WMI_CMD_ID cmd_id)
{
    A_STATUS status;
    struct cookie *cookie;


#if WMI_RECORDING
    if (wmi_handle->wmi_enable) {
        switch(cmd_id) {
        case WMI_VDEV_CREATE_CMDID:
        case WMI_VDEV_DELETE_CMDID:
        case WMI_VDEV_START_REQUEST_CMDID:
        case WMI_VDEV_RESTART_REQUEST_CMDID:
        case WMI_VDEV_UP_CMDID:
        case WMI_VDEV_STOP_CMDID:
        case WMI_VDEV_DOWN_CMDID:
        case WMI_VDEV_SET_PARAM_CMDID:
        case WMI_PDEV_SET_CHANNEL_CMDID:
        case WMI_PDEV_SET_PARAM_CMDID:
        case WMI_PDEV_SET_WMM_PARAMS_CMDID:
        case WMI_PDEV_SUSPEND_CMDID:
        case WMI_PDEV_RESUME_CMDID:
        case WMI_PEER_CREATE_CMDID:
        case WMI_PEER_DELETE_CMDID:
        case WMI_PEER_FLUSH_TIDS_CMDID:
        case WMI_PEER_SET_PARAM_CMDID:
        case WMI_PEER_ASSOC_CMDID:
        case WMI_AP_PS_PEER_PARAM_CMDID:
          wmi_add_to_circ(wmi_handle, (char *) wbuf_raw_data(buf), len, cmd_id);
        default:
          break;
        }
    }
#endif

    if (wbuf_push(buf, sizeof(WMI_CMD_HDR)) == NULL) {
        wbuf_free(buf);
        return -ENOMEM;
    }

    if (wmi_handle->wmi_stopinprogress) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "WMI  stop in progress \n");
        wbuf_free(buf);
        return -ENOMEM;
    }

    WMI_SET_FIELD(wbuf_header(buf), WMI_CMD_HDR, COMMANDID, cmd_id);
    //WMI_CMD_HDR_SET_DEVID(cmd_hdr, 0); // unused

    cookie = ol_alloc_cookie(wmi_handle->scn_handle);
    if (!cookie) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : Cookie alloc Failed for cmd_id : %0x, WMI handle = %p\n",__func__,cmd_id,wmi_handle);
        wbuf_free(buf);
        return -ENOMEM;
    }

    cookie->PacketContext = buf;
    SET_HTC_PACKET_INFO_TX(&cookie->HtcPkt,
                           cookie,
                           wbuf_header(buf),
                           len+sizeof(WMI_CMD_HDR),
                           /* htt_host_data_dl_len(buf)+20 */
                           wmi_handle->wmi_endpoint_id,
                           0/*htc_tag*/);

    SET_HTC_PACKET_NET_BUF_CONTEXT(&cookie->HtcPkt, buf);

#ifndef REMOVE_INIT_DEBUG_CODE
    /* To be removed code for init debug only */
    if(cmd_id == WMI_INIT_CMDID)
    {
        A_UINT8 *ptr = NULL;
        ptr = (uint8_t *)wbuf_header(buf) + 4;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "wmi layer Check this %x \n", *(uint32_t *)(ptr + 88));
    }
#endif


    status = htc_send_pkt(wmi_handle->htc_handle, &cookie->HtcPkt);

    if (status != A_OK) {
        ol_free_cookie(wmi_handle->scn_handle, cookie);
        wbuf_free(buf);
    }

    return ((status == A_OK) ? EOK : -1);
}


/* WMI Event handler register API */

int wmi_unified_register_event_handler(wmi_unified_t wmi_handle,
                                       WMI_EVT_ID event_id,
                                       wmi_unified_event_handler handler_func,
                                       void* cookie)
{
    u_int16_t handler_id;
    handler_id = (event_id - WMI_START_EVENTID);
    if (handler_id >= WMI_UNIFIED_MAX_EVENT) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : unkown event id : 0x%x  event handler id 0x%x \n",
                __func__, event_id, handler_id);
        return -1;
    }
    if (wmi_handle->event_handler[handler_id]) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : event handler is already registered: event id 0x%x \n",
                __func__, event_id);
        return -1;
    }
    wmi_handle->event_handler[handler_id] = handler_func;
    wmi_handle->event_handler_cookie[handler_id] = cookie;
    return 0;
}

int wmi_unified_unregister_event_handler(wmi_unified_t wmi_handle,
                                       WMI_EVT_ID event_id)
{
    u_int16_t handler_id;
    handler_id = (event_id - WMI_START_EVENTID);
    if (wmi_handle == NULL) {
        qdf_print("wmi_handle already freed\n");
        return 0;
    }

    if (handler_id >= WMI_UNIFIED_MAX_EVENT) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : unkown event id : 0x%x  event handler id 0x%x \n",
                __func__, event_id, handler_id);
        return -1;
    }
    if (wmi_handle->event_handler[handler_id] == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : event handler is not registered: event id 0x%x \n",
                __func__, event_id);
        return -1;
    }
    wmi_handle->event_handler[handler_id] = NULL;
    wmi_handle->event_handler_cookie[handler_id] = NULL;
    return 0;
}


static int wmi_unified_event_rx(struct wmi_unified *wmi_handle, wmi_buf_t evt_buf)
{
    u_int16_t id;
    u_int8_t *event;
    u_int16_t len;
    int status = -1;
    u_int16_t handler_id;

    ASSERT(evt_buf != NULL);

    id = WMI_GET_FIELD(wbuf_header(evt_buf), WMI_CMD_HDR, COMMANDID);
    handler_id = (id - WMI_START_EVENTID);

    if (wbuf_pull(evt_buf, sizeof(WMI_CMD_HDR)) == NULL) {
        //A_DPRINTF(DBG_WMI, (DBGFMT "bad packet 1\n", DBGARG));
        //wmip->wmi_stats.cmd_len_err++;
        goto end;
    }
    if (handler_id >= WMI_UNIFIED_MAX_EVENT) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : unkown event id : 0x%x  event handler id 0x%x \n",
                __func__, id, handler_id);
        goto end;
    }

    event = wbuf_header(evt_buf);
    len = wbuf_get_pktlen(evt_buf);


    if (!wmi_handle->event_handler[handler_id]) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s : no registered event handler : event id 0x%x \n",
                __func__, id);
        goto end;
    }

    /*
    * Fill the tail of the buffer with 0x0.
    * This is just in case the target is using an older, shorter definition
    * of the message and thus doesn't provide as much information as the
    * host expects.  Filling these unspecified message fields with 0x0
    * allows the WMI event message handler callback functions to process
    * the message fields as if they had been provided, since 0x0 should
    * be interpreted as a no-op value for all new fields.
    * (Alternatively, since the length of the data provided by the target
    * is provided to the callback function, the callback function can
    * explicitly check how many of the message fields were actually
    * filled in by the target.)
    */
    OS_MEMZERO(event+len, wbuf_get_tailroom(evt_buf));

    /* Call the WMI registered event handler */
    status = wmi_handle->event_handler[handler_id](wmi_handle->scn_handle, event, len,
                                           wmi_handle->event_handler_cookie[handler_id]);

end:
    wbuf_free(evt_buf);
    return status;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
wmi_service_ready_event_rx(struct wmi_unified *wmi_handle, wmi_buf_t evt_buf, int len)
#else
wmi_service_ready_event_rx(struct wmi_unified *wmi_handle, A_UINT8 *datap, int len)
#endif
{
    int status = A_OK;
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
    wmi_service_ready_event *ev = (wmi_service_ready_event *)datap;
#endif

    if (len < sizeof(wmi_service_ready_event)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:  WMI UNIFIED SERVICE READY event - invalid length \n", __func__);
        status = A_EINVAL;
        goto end;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO"%s:  WMI UNIFIED SERVICE READY event \n", __func__);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    status = create_queue_work(wmi_handle->scn_handle, evt_buf);
    if(status) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Failed to queue work to handle coherent memory alloc \n", __func__);
    }
#else
    ol_ath_service_ready_event(wmi_handle->scn_handle, ev);
#endif

end:
    return status;
}

static int
wmi_ready_event_rx(struct wmi_unified *wmi_handle, A_UINT8 *datap, int len)
{
    wmi_ready_event *ev = (wmi_ready_event *)datap;

    if (len < sizeof(wmi_ready_event)) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:  WMI UNIFIED READY event - invalid length \n", __func__);
        return A_EINVAL;
    }

    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s:  WMI UNIFIED READY event \n", __func__);
    ol_ath_ready_event(wmi_handle->scn_handle, ev);


    return A_OK;
}

/*
 * Temporarily added to support older WMI events. We should move all events to unified
 * when the target is ready to support it.
 */
void
wmi_control_rx(void *ctx, HTC_PACKET *htc_packet)
{
    u_int16_t id;
    u_int8_t *data;
    u_int32_t len;
    int status = EOK;
    wmi_buf_t evt_buf;
    struct wmi_unified *wmi_handle = (struct wmi_unified *) ctx;

    evt_buf =  (wmi_buf_t)  htc_packet->pPktContext;

    id = WMI_GET_FIELD(wbuf_header(evt_buf), WMI_CMD_HDR, COMMANDID);

    if ((id >= WMI_START_EVENTID) && (id <= WMI_END_EVENTID)) {
        status = wmi_unified_event_rx(wmi_handle, evt_buf);
        return ;
    }

    if (wbuf_pull(evt_buf, sizeof(WMI_CMD_HDR)) == NULL) {
        status = -1;
        goto end;
    }

    data = wbuf_header(evt_buf);
    len = wbuf_get_pktlen(evt_buf);

    switch(id)
    {
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Unhandled WMI command %d\n", __func__, id);
            break;
        case WMI_SERVICE_READY_EVENTID:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
            status = wmi_service_ready_event_rx(wmi_handle, evt_buf, len);
#else
            status = wmi_service_ready_event_rx(wmi_handle, data, len);
#endif
            break;
        case WMI_READY_EVENTID:
            status = wmi_ready_event_rx(wmi_handle, data, len);
            break;
        case WMI_WLAN_VERSION_EVENTID:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Handle WMI_VERSION_EVENTID\n", __func__);
            break;
        case WMI_REGDOMAIN_EVENTID:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: Handle WMI_REGDOMAIN_EVENTID\n", __func__);
            break;
        case WMI_DEBUG_MESG_EVENTID:
            dbglog_message_handler(wmi_handle->scn_handle, evt_buf);
            return;
    }

end:
    wbuf_free(evt_buf);
}

#if WMI_RECORDING

unsigned char wmi_ring_size = 64;
module_param(wmi_ring_size, byte, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(wmi_ring_size,
        "Ring size for WMI commands ");

static const char *wmi_id_to_name(WMI_CMD_ID wmi_cmd)
{
  switch (wmi_cmd) {
  case WMI_VDEV_CREATE_CMDID:
    return "WMI_VDEV_CREATE_CMDID";
  case WMI_VDEV_DELETE_CMDID:
    return "WMI_VDEV_DELETE_CMDID";
  case WMI_VDEV_START_REQUEST_CMDID:
    return "WMI_VDEV_START_REQUEST_CMDID";
  case WMI_VDEV_RESTART_REQUEST_CMDID:
    return "WMI_VDEV_RESTART_REQUEST_CMDID";
  case WMI_VDEV_UP_CMDID:
    return "WMI_VDEV_UP_CMDID";
  case WMI_VDEV_STOP_CMDID:
    return "WMI_VDEV_STOP_CMDID";
  case WMI_VDEV_DOWN_CMDID:
    return "WMI_VDEV_DOWN_CMDID";
  case WMI_VDEV_SET_PARAM_CMDID:
    return "WMI_VDEV_SET_PARAM_CMDID";

  case WMI_PDEV_SET_CHANNEL_CMDID:
    return "WMI_PDEV_SET_CHANNEL_CMDID";
  case WMI_PDEV_SET_PARAM_CMDID:
    return "WMI_PDEV_SET_PARAM_CMDID";
  case WMI_PDEV_SET_WMM_PARAMS_CMDID:
    return "WMI_PDEV_SET_WMM_PARAMS_CMDID";
  case WMI_PDEV_SUSPEND_CMDID:
    return "WMI_PDEV_SUSPEND_CMDID";
  case WMI_PDEV_RESUME_CMDID:
    return "WMI_PDEV_RESUME_CMDID";

  case WMI_PEER_CREATE_CMDID:
    return "WMI_PEER_CREATE_CMDID";
  case WMI_PEER_DELETE_CMDID:
    return "WMI_PEER_DELETE_CMDID";
  case WMI_PEER_FLUSH_TIDS_CMDID:
    return "WMI_PEER_FLUSH_TIDS_CMDID";
  case WMI_PEER_SET_PARAM_CMDID:
    return "WMI_PEER_SET_PARAM_CMDID";
  case WMI_PEER_ASSOC_CMDID:
    return "WMI_PEER_ASSOC_CMDID";
  case WMI_AP_PS_PEER_PARAM_CMDID:
    return "WMI_AP_PS_PEER_PARAM_CMDID";
  default:
    return "Bogus";
  }
}

static bool is_pow_of_2(unsigned char x)
{
  if (x) {
    return ((x & (x - 1)) == 0);
  } else {
    return 0;
  }
}

static int wmi_circ_init(struct wmi_unified *h)
{
  struct wmi_circbuf *wmi_circ = &h->buf;

  if (!is_pow_of_2(wmi_ring_size)) {
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ring size should be power of 2..\n");
    return 0;
  }

  wmi_circ->length = 0;
  wmi_circ->tail = 0;
  wmi_circ->wmi = qdf_mem_malloc(wmi_ring_size * sizeof(wmi_circ_item_t));
  if(!wmi_circ->wmi) {
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "no memory for ring buffer..\n");
    return 0;
  }
  qdf_spinlock_create(&wmi_circ->wmi_circ_lock);
  h->wmi_enable = 0;

  return 1;
}

static inline void wmi_circ_free(struct wmi_unified* h)
{
    if(h->buf.wmi) {
      qdf_mem_free(h->buf.wmi);
      qdf_spinlock_destroy(&h->buf.wmi_circ_lock);
    }
}

void wmi_add_to_circ(wmi_unified_t h, char *cmd, int len, WMI_CMD_ID id)
{
  struct wmi_circbuf *wmi_circ = &h->buf;
  wmi_circ_item_t *wmi;

  if (!wmi_circ->wmi) {
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "wmi ring buffer not initialized!\n");
    return;
  }

  qdf_spin_lock(&wmi_circ->wmi_circ_lock);
  wmi = &(wmi_circ->wmi[wmi_circ->tail]);
  wmi->len = (len < WMI_CMD_LEN) ? len: WMI_CMD_LEN;
  memcpy(wmi->wmi_cmdbuf, cmd, wmi->len);
  wmi->id = id;

  wmi_circ->tail = (wmi_circ->tail + 1) & (wmi_ring_size - 1);
  wmi_circ->length++;
  qdf_spin_unlock(&wmi_circ->wmi_circ_lock);
}

/* procfs routines*/
static int proc_wmi_ring_show(struct seq_file *m, void *v)
{
  wmi_unified_t h = (wmi_unified_t) m->private;
  struct wmi_circbuf *wmi_circ = &h->buf;
  int pos, nread, outlen;
  int i;

  if(!wmi_circ->length) {
    return seq_printf(m,"no elements to read from ring buffer!\n");
  }

  if (wmi_circ->length <= wmi_ring_size) {
    nread = wmi_circ->length;
  } else {
    nread = wmi_ring_size;
  }

  if (wmi_circ->tail == 0) {
    /* tail can be 0 after wrap-around */
    pos = wmi_ring_size - 1;
  } else {
    pos = wmi_circ->tail - 1;
  }

  outlen = 0;
  qdf_spin_lock(&wmi_circ->wmi_circ_lock);
  while (nread--) {
    wmi_circ_item_t *wmi;

    wmi = &(wmi_circ->wmi[pos]);
    outlen += seq_printf(m, "ID = %s\n", wmi_id_to_name(wmi->id));
    outlen += seq_printf(m, "CMD = ");
    for(i = 0;i < wmi->len; i++)
      outlen += seq_printf(m, "%x ", wmi->wmi_cmdbuf[i]);
    outlen += seq_printf(m, "\n");

    if (pos == 0)
      pos = wmi_ring_size - 1;
    else
      pos--;
  }
  qdf_spin_unlock(&wmi_circ->wmi_circ_lock);

  return 0;
}

static ssize_t proc_wmi_show(struct seq_file *m, void *v)
{
  wmi_unified_t h = (wmi_unified_t) m->private;

  seq_printf(m, "%d\n", h->wmi_enable);

  return 0;
}

static int proc_wmi_ring_size_show(struct seq_file *m, void *v)
{
  return seq_printf(m, "%d\n", wmi_ring_size);
}

static ssize_t proc_wmi_ring_write(struct file *file, const char __user *buf,
                                   size_t count, loff_t *ppos)
{
  int k;
  wmi_unified_t h =  PDE(file->f_path.dentry->d_inode)->data;
  struct wmi_circbuf *wmi_circ = &h->buf;

  sscanf(buf, "%d", &k);
  if(k != 0) {
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "Wrong input, echo 0 to clear the wmi buffer\n");
    return -EINVAL;
  }

  qdf_spin_lock(&wmi_circ->wmi_circ_lock);
  memset(wmi_circ->wmi, 0, wmi_ring_size * sizeof(wmi_circ_item_t));
  wmi_circ->length = 0;
  wmi_circ->tail = 0;
  qdf_spin_unlock(&wmi_circ->wmi_circ_lock);

  return count;
}

static ssize_t proc_wmi_write(struct file *file, const char __user *buf,
                                   size_t count, loff_t *ppos)
{
  wmi_unified_t h =  PDE(file->f_path.dentry->d_inode)->data;
  int k;

  sscanf(buf, "%d", &k);
  if((k != 0) && (k != 1)) {
    return -EINVAL;
  }

  h->wmi_enable = k;
  return count;
}

static ssize_t proc_wmi_ring_size_write(struct file *file, const char __user *buf,
                                   size_t count, loff_t *ppos)
{
  return -EINVAL;
}
#ifndef MAX_RADIO_CNT
#define MAX_RADIO_CNT 3
#endif

struct wmi_proc_info {
    const char *name;
    struct proc_dir_entry *de[MAX_RADIO_CNT];
    struct file_operations *ops;
};

#define PROC_FOO(func_base) { .name = #func_base, .ops = &proc_##func_base##_ops }

#define GENERATE_PROC_STRUCTS(func_base)				\
	static int proc_##func_base##_open(struct inode *inode, \
					   struct file *file)		\
	{								\
		struct proc_dir_entry *dp = PDE(inode);			\
        return single_open(file, proc_##func_base##_show, dp->data);    \
    } \
									\
									\
	static struct file_operations proc_##func_base##_ops = { \
		.open		= proc_##func_base##_open,	\
		.read		= seq_read,				\
		.llseek		= seq_lseek,				\
        .write      = proc_##func_base##_write,	\
		.release	= single_release,			\
	};

GENERATE_PROC_STRUCTS(wmi_ring);
GENERATE_PROC_STRUCTS(wmi);
GENERATE_PROC_STRUCTS(wmi_ring_size);

struct wmi_proc_info wmi_proc_infos[] = {
  PROC_FOO(wmi_ring),
  PROC_FOO(wmi),
  PROC_FOO(wmi_ring_size),
};

#define NUM_PROC_INFOS (sizeof(wmi_proc_infos) / sizeof(wmi_proc_infos[0]))

void wmi_proc_create(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id)
{
  int i;

  if (par_entry == NULL || (id < 0) || (id >= MAX_RADIO_CNT))
    goto out;

  for (i = 0; i < NUM_PROC_INFOS; ++i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
            wmi_proc_infos[i].de[id] = proc_create(wmi_proc_infos[i].name,
                                0644, par_entry, wmi_proc_infos[i].ops);
#else
            wmi_proc_infos[i].de[id] = create_proc_entry(wmi_proc_infos[i].name,
                                       0644, par_entry);
#endif
            if (wmi_proc_infos[i].de[id] == NULL) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Proc Entry creation failed!\n", __func__);
                goto out;
            }
            wmi_proc_infos[i].de[id]->data = wmi_handle;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
            wmi_proc_infos[i].de[id]->proc_fops = wmi_proc_infos[i].ops;
#endif
  }


  return;

out:
  QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: Proc Entry creation failed!\n", __func__);
  wmi_circ_free(wmi_handle);
  return;
}


void wmi_proc_remove(wmi_unified_t wmi_handle, struct proc_dir_entry *par_entry, int id)
{
  if (par_entry && (!(id < 0) || (id >= MAX_RADIO_CNT))) {
    int i;
    for (i = 0; i < NUM_PROC_INFOS; ++i) {
        if(wmi_proc_infos[i].de[id]) {
            remove_proc_entry(wmi_proc_infos[i].name, par_entry);
            wmi_proc_infos[i].de[id] = NULL;
        }
    }
  }
}

#endif // WMI_RECORDING

/* WMI Initialization functions */

void *
wmi_unified_attach(ol_scn_t scn_handle, osdev_t osdev)
{
    struct wmi_unified *wmi_handle;
    wmi_handle = (struct wmi_unified *)OS_MALLOC(osdev, sizeof(struct wmi_unified), GFP_ATOMIC);
    if (wmi_handle == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "allocation of wmi handle failed %d \n",sizeof(struct wmi_unified));
        return NULL;
    }
    OS_MEMZERO(wmi_handle, sizeof(struct wmi_unified));
    wmi_handle->scn_handle = scn_handle;
    wmi_handle->osdev = osdev;
#if WMI_RECORDING
    if (!wmi_circ_init(wmi_handle)) {
      qdf_print("Error while creating ring buffer for wmi debug!!\n");
    }
#endif

    return wmi_handle;
}

void
wmi_unified_detach(struct wmi_unified* wmi_handle)
{
    if (wmi_handle != NULL) {
#if WMI_RECORDING
      wmi_circ_free(wmi_handle);
#endif
        OS_FREE(wmi_handle);
        wmi_handle = NULL;
    }
}

void   wmi_htc_tx_complete(void *ctx,HTC_PACKET *htc_pkt)
{

    wmi_buf_t wmi_cmd_buf=GET_HTC_PACKET_NET_BUF_CONTEXT(htc_pkt);
    struct wmi_unified *wmi_handle = (struct wmi_unified *)ctx;
    struct cookie *cookie = htc_pkt->pPktContext;
    int id;

    id = WMI_GET_FIELD(wbuf_header(wmi_cmd_buf), WMI_CMD_HDR, COMMANDID);
    ASSERT(wmi_cmd_buf);
    wbuf_free(wmi_cmd_buf);
    ol_free_cookie(wmi_handle->scn_handle , cookie);
    return;
}

int
wmi_unified_connect_htc_service(struct wmi_unified * wmi_handle, void *htc_handle)
{

    int status;
    HTC_SERVICE_CONNECT_RESP response;
    HTC_SERVICE_CONNECT_REQ connect;

    OS_MEMZERO(&connect, sizeof(connect));
    OS_MEMZERO(&response, sizeof(response));

    /* meta data is unused for now */
    connect.pMetaData = NULL;
    connect.MetaDataLength = 0;
    /* these fields are the same for all service endpoints */
    connect.EpCallbacks.pContext = wmi_handle;
    connect.EpCallbacks.EpTxCompleteMultiple = NULL /* Control path completion ar6000_tx_complete */;
    connect.EpCallbacks.EpRecv = wmi_control_rx /* Control path rx */;
    connect.EpCallbacks.EpRecvRefill = NULL /* ar6000_rx_refill */;
    connect.EpCallbacks.EpSendFull = NULL /* ar6000_tx_queue_full */;
    connect.EpCallbacks.EpTxComplete = wmi_htc_tx_complete /* ar6000_tx_queue_full */;

    /* connect to control service */
    connect.service_id = WMI_CONTROL_SVC;

    if ((status = htc_connect_service(htc_handle, &connect, &response)) != EOK)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Failed to connect to WMI CONTROL  service status:%d \n",  status);
        return -1;;
    }
    wmi_handle->wmi_endpoint_id = response.Endpoint;
    wmi_handle->htc_handle = htc_handle;

    return EOK;
}


ol_scn_t wmi_get_scn_handle(struct wmi_unified *wmi_handle)
{
    return wmi_handle->scn_handle;
}
#endif
