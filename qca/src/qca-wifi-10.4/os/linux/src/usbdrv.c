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


#include <osdep.h>
#include "htc_thread.h"

#if ZM_USB_STREAM_MODE
extern void __ahdecl wmi_reg_write_single(void * wmi_handle, u_int reg, u_int32_t val);
#endif

extern void HIF_UsbDataOut_Callback(void *phifhdl, struct sk_buff * context);
extern void HIF_UsbDataIn_Callback(void *phifhdl, struct sk_buff * buf);
extern void HIF_UsbCmdOut_Callback(void *phifhdl, struct sk_buff * context);
extern void HIF_UsbMsgIn_Callback(void *phifhdl, struct sk_buff * buf);
extern void HIF_Usb_Stop_Callback(void *phifhdl, void *pwmihdl, uint8_t usb_status);

uint32_t athLnxUsbIn(osdev_t osdev, UsbRxUrbContext *RxUrbCtx);
uint32_t athLnxUsbSubmitTxData(osdev_t osdev, HIFUSBTxPipe *pipe);
void athLnx_rx_streammode_timeout_change(osdev_t osdev, u_int32_t val);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))||(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19))
void athLnxUsbDataIn_callback(urb_t *urb);
void athLnxUsbDataOut_callback(urb_t *urb);
#else
void athLnxUsbDataIn_callback(urb_t *urb, struct pt_regs *regs);
void athLnxUsbDataOut_callback(urb_t *urb, struct pt_regs *regs);
#endif

/* Function delcaration for FW recovery */
void MpHtcSuspend(osdev_t osdev);
void MpHtcResume(osdev_t osdev);
void ath_usb_vap_restart(struct net_device *dev);

/* define EVENT ID for Worker Queue */
#define ATH_RECOVER_EVENT                     1

//  ?????
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) /* tune me! */
#define SUBMIT_URB(u,f)       usb_submit_urb(u,f)
#define USB_ALLOC_URB(u,f)    usb_alloc_urb(u,f)
#else
#define SUBMIT_URB(u,f)       usb_submit_urb(u)
#define USB_ALLOC_URB(u,f)    usb_alloc_urb(u)
#endif

#if ZM_USB_TX_STREAM_MODE
#define UPSTREAM_MODE_TIMEOUT_REGISTER      0x10114
#define UPSTREAM_MODE_TIMEOUT_ORIVALUE      0xa0
#define UPSTREAM_MODE_TIMEOUT_ENLARGE_VALUE 0x420

#endif /*ZM_USB_TX_STREAM_MODE*/

#define hif_usb_assert(_cond)    ({     \
        int __ret = !(_cond);                  \
		if (__ret) {                  \
			dump_stack();               \
			panic("Asserting %s:%d for condition = !%s\n",   \
							__FUNCTION__, __LINE__, #_cond);  \
		}                               \
		__ret;                            \
})


static struct sk_buff *
hif_usb_alloc_skb(uint32_t size, uint32_t reserve, uint32_t align)
{
    struct sk_buff *skb = NULL;

	size += align;
		    
	skb = dev_alloc_skb(size);
	if (!skb)
		return NULL;
							    
	if (!align) return skb;								
	reserve += (ALIGN((unsigned long)skb->data, align) - (unsigned long)skb->data);

	skb_reserve(skb, reserve);
														    
	hif_usb_assert(((unsigned long)skb->data % align) == 0);

	return skb;

}

static void allocTxUrbs(osdev_t osdev, HIFUSBTxPipe *pipe)
{
    int i;

    for (i = 0; i < ZM_MAX_TX_URB_NUM; i++)
    {
        pipe->TxUrbCtx[i].index = i;
        pipe->TxUrbCtx[i].inUse = 0;
        pipe->TxUrbCtx[i].buf   = NULL;
        pipe->TxUrbCtx[i].osdev = osdev;
        pipe->TxUrbCtx[i].pipe  = (void *)pipe;        
        pipe->TxUrbCtx[i].urb   = USB_ALLOC_URB(0, GFP_KERNEL);

        if (pipe->TxUrbCtx[i].urb == 0)
        {
            int j;

            /* Free all urbs */
            for (j = 0; j < i; j++)
            {
                usb_free_urb(pipe->TxUrbCtx[j].urb);
            }
            return;
        }
    }
}

u_int32_t inline A_MS_TICKGET(void)
{
#if HZ == 1000
    /* If the HZ is set to 1000, we just return jiffies. */
    return jiffies;
#else
    return get_cycles() >> ZM_1MS_SHIFT_BITS;
#endif
}

void athLnxPerSecTimer(unsigned long param)
{
    osdev_t             osdev = (osdev_t) param;

#if ZM_USB_TX_STREAM_MODE
    static  u_int8_t    rxtimeoutregsetflag = 0;
    u_int32_t           original_val = UPSTREAM_MODE_TIMEOUT_ORIVALUE;
#endif

    atomic_set(&(osdev->txFrameNumPerSecond), atomic_read(&(osdev->txFrameCnt)));
    atomic_set(&(osdev->txFrameCnt), 0);

#if ZM_USB_TX_STREAM_MODE
    if(atomic_read(&osdev->txFrameNumPerSecond) > ZM_L1_TX_PACKET_THR &&
        rxtimeoutregsetflag == 0)
    {
        /* I should read before write*/
        athLnx_rx_streammode_timeout_change(osdev, UPSTREAM_MODE_TIMEOUT_ENLARGE_VALUE);
        rxtimeoutregsetflag = 1;
    } else if(atomic_read(&osdev->txFrameNumPerSecond) < ZM_L1_TX_PACKET_THR &&
        rxtimeoutregsetflag == 1)
    {
        athLnx_rx_streammode_timeout_change(osdev, original_val);
        rxtimeoutregsetflag = 0;
    }
#endif

    mod_timer(&(osdev->one_sec_timer), jiffies + HZ);
}


void athSetBulkType(struct usb_endpoint_descriptor *endpoint)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)) 
     endpoint->bmAttributes &= ~USB_ENDPOINT_XFERTYPE_MASK;
     endpoint->bmAttributes |= USB_ENDPOINT_XFER_BULK;
     endpoint->bInterval = 0;
#endif
}

#ifdef NBUF_PREALLOC_POOL
int athLnxAllocRegInBuf(osdev_t osdev)
{
    osdev->regUsbReadBuf = hif_usb_alloc_skb(ZM_USB_REG_MAX_BUF_SIZE, 0, 0);
    if(osdev->regUsbReadBuf == NULL) {
        return 0;
    }
    return 1;
}

void athLnxFreeRegInBuf(osdev_t osdev)
{
    if(osdev->regUsbReadBuf != NULL) {
        dev_kfree_skb_any(osdev->regUsbReadBuf);
    }
    return; 
} 
#endif

int athLnxAllocAllUrbs(osdev_t osdev)
{
    struct usb_interface *interface = osdev->interface;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
    struct usb_interface_descriptor *iface_desc = &interface->altsetting[0];
#else
    struct usb_host_interface *iface_desc = &interface->altsetting[0];
#endif

    struct usb_endpoint_descriptor *endpoint;
    int i;

    /* init lock */
    spin_lock_init(&(osdev->cs_lock));
    spin_lock_init(&(osdev->CmdUrbLock));


    /* descriptor matches, let's find the endpoints needed */
    /* check out the endpoints */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))    
    for (i = 0; i < iface_desc->bNumEndpoints; ++i)
    {
        endpoint = &iface_desc->endpoint[i];
#else
    for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i)
    {
        endpoint = &iface_desc->endpoint[i].desc;
#endif      
        if ((endpoint->bEndpointAddress & 0x80) &&
            ((endpoint->bmAttributes & 3) == 0x02))
        {
            /* we found a bulk in endpoint */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ep[%d] bulk in: wMaxPacketSize = 0x%x\n", 
				i, le16_to_cpu(endpoint->wMaxPacketSize));
        }

        if (((endpoint->bEndpointAddress & 0x80) == 0x00) &&
            ((endpoint->bmAttributes & 3) == 0x02))
        {
            /* we found a bulk out endpoint */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ep[%d] bulk out: wMaxPacketSize = 0x%x\n", 
				i, le16_to_cpu(endpoint->wMaxPacketSize));
        }

        if ((endpoint->bEndpointAddress & 0x80) &&
            ((endpoint->bmAttributes & 3) == 0x03))
        {
            /* we found a interrupt in endpoint */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ep[%d] interrupt in: wMaxPacketSize = 0x%x\n", 
				i, le16_to_cpu(endpoint->wMaxPacketSize));
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ep[%d] interrupt in: int_interval = %d\n", 
				i, endpoint->bInterval);
#ifdef ZM_USB_WAR_EP3_INTTOBULK
            athSetBulkType(endpoint);
#endif            
        }
    
        if (((endpoint->bEndpointAddress & 0x80) == 0x00) &&
            ((endpoint->bmAttributes & 3) == 0x03))
        {
            /* we found a interrupt out endpoint */
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ep[%d] interrupt out: wMaxPacketSize = 0x%x\n", 
				i, le16_to_cpu(endpoint->wMaxPacketSize));
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "ep[%d] interrupt out: int_interval = %d\n", 
				i, endpoint->bInterval);
			
            athSetBulkType(endpoint);
        }
    }

    /* Allocate all Tx URBs */
    allocTxUrbs(osdev, &osdev->TxPipe);
    allocTxUrbs(osdev, &osdev->HPTxPipe);
#if 0        
    for (i = 0; i < ZM_MAX_TX_URB_NUM; i++)
    {
        osdev->WlanTxDataUrb[i] = USB_ALLOC_URB(0, GFP_KERNEL);
        osdev->TxUrbCtx[i].buf = NULL;
        osdev->TxUrbCtx[i].osdev = osdev;

        if (osdev->WlanTxDataUrb[i] == 0)
        {
            int j;

            /* Free all urbs */
            for (j = 0; j < i; j++)
            {
                usb_free_urb(osdev->WlanTxDataUrb[j]);
            }

            return 0;
        }
    }
#endif
    /* Allocate all Rx URBs */
    for (i = 0; i < ZM_MAX_RX_URB_NUM; i++)
    {
        osdev->RxUrbCtx[i].index = i;
        osdev->RxUrbCtx[i].inUse = 0;
        //osdev->RxUrbCtx[i].buf   = NULL;
        osdev->RxUrbCtx[i].osdev = osdev;
        osdev->RxUrbCtx[i].WlanRxDataUrb = USB_ALLOC_URB(0, GFP_KERNEL);

        if (osdev->RxUrbCtx[i].WlanRxDataUrb == 0)
        {
            int j;

            /* Free all urbs */
            for (j = 0; j < i; j++)
            {
                usb_free_urb(osdev->RxUrbCtx[j].WlanRxDataUrb);
            }

            for (j = 0; j < ZM_MAX_TX_URB_NUM; j++)
            {
                usb_free_urb(osdev->TxPipe.TxUrbCtx[j].urb);
                usb_free_urb(osdev->HPTxPipe.TxUrbCtx[j].urb);
            }

            return 0;
        }
    }

    /* Allocate Register Read/Write USB */
    for (i=0; i<MAX_CMD_URB; i++)
    {
        osdev->UsbCmdOutCtxs[i].index = i;
        osdev->UsbCmdOutCtxs[i].inUse = 0;
        osdev->UsbCmdOutCtxs[i].buf = NULL;
        osdev->UsbCmdOutCtxs[i].osdev = osdev;
        osdev->UsbCmdOutCtxs[i].urb = USB_ALLOC_URB(0, GFP_KERNEL);        
    }

    osdev->RegInUrb = USB_ALLOC_URB(0, GFP_KERNEL);

    return 1;
}

void athLnxFreeAllUrbs(osdev_t osdev)
{
    int i;

    /* Free all Tx URBs and USB Tx Buffers */
    for (i = 0; i < ZM_MAX_TX_URB_NUM; i++)
    {
        if (osdev->TxPipe.TxUrbCtx[i].urb != NULL)
        {
            usb_free_urb(osdev->TxPipe.TxUrbCtx[i].urb);
        }

        if (osdev->TxPipe.TxUrbCtx[i].txUsbBuf != NULL)
        {
           kfree(osdev->TxPipe.TxUrbCtx[i].txUsbBuf);
        }

        if (osdev->HPTxPipe.TxUrbCtx[i].urb != NULL)
        {
            usb_free_urb(osdev->HPTxPipe.TxUrbCtx[i].urb);
        }

        if (osdev->HPTxPipe.TxUrbCtx[i].txUsbBuf != NULL)
        {
           kfree(osdev->HPTxPipe.TxUrbCtx[i].txUsbBuf);
        }
    }

    /* Free all Rx URBs */
    for (i = 0; i < ZM_MAX_RX_URB_NUM; i++)
    {
        if (osdev->RxUrbCtx[i].WlanRxDataUrb != NULL)
        {
            usb_free_urb(osdev->RxUrbCtx[i].WlanRxDataUrb);
        }
    }

    /* Free USB Register Read/Write URB */
    for (i=0; i<MAX_CMD_URB; i++)
    {
        if (osdev->UsbCmdOutCtxs[i].inUse != 0)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "error when free urb (%d)\n", osdev->UsbCmdOutCtxs[i].index);
        }
        if (osdev->UsbCmdOutCtxs[i].urb != NULL)
        { 
            usb_free_urb(osdev->UsbCmdOutCtxs[i].urb);
        }
    }    
    usb_free_urb(osdev->RegInUrb);
}

void athLnxUnlinkAllTxUrbs(osdev_t osdev)
{
    int i;

    for (i = 0; i < ZM_MAX_TX_URB_NUM; i++)
    {
        if (osdev->TxPipe.TxUrbCtx[i].urb != NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
            osdev->TxPipe.TxUrbCtx[i].urb->transfer_flags &= 
				~URB_ASYNC_UNLINK;
#endif
            usb_kill_urb(osdev->TxPipe.TxUrbCtx[i].urb);
        }
        if (osdev->HPTxPipe.TxUrbCtx[i].urb != NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
            osdev->HPTxPipe.TxUrbCtx[i].urb->transfer_flags &= 
				~URB_ASYNC_UNLINK;
#endif
            usb_kill_urb(osdev->HPTxPipe.TxUrbCtx[i].urb);
        }
#if 0
        if (osdev->MPTxPipe.TxUrbCtx[i].urb != NULL)
        {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
            osdev->MPTxPipe.TxUrbCtx[i].urb->transfer_flags &= ~URB_ASYNC_UNLINK;
#endif
            usb_kill_urb(osdev->MPTxPipe.TxUrbCtx[i].urb);
        }
#endif        
    }
    return ;
}

void athLnxUnlinkAllUrbs(osdev_t osdev)
{
    int i;

    /* Unlink all Tx URBs */
    athLnxUnlinkAllTxUrbs(osdev);

    /* Unlink all Rx URBs */
    for (i = 0; i < ZM_MAX_RX_URB_NUM; i++)
    {
        if (osdev->RxUrbCtx[i].WlanRxDataUrb != NULL && osdev->RxUrbCtx[i].inUse == 1)
        {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
            osdev->RxUrbCtx[i].WlanRxDataUrb->transfer_flags &= ~URB_ASYNC_UNLINK;
#endif
            usb_kill_urb(osdev->RxUrbCtx[i].WlanRxDataUrb);
        }
    }

    /* Unlink USB Register Read/Write URB */
    for (i = 0; i < MAX_CMD_URB; i++)
    {
        if (osdev->UsbCmdOutCtxs[i].urb != NULL)
        {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
            osdev->UsbCmdOutCtxs[i].urb->transfer_flags &= ~URB_ASYNC_UNLINK;
#endif
            usb_kill_urb(osdev->UsbCmdOutCtxs[i].urb);
        }
    }    

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
    osdev->RegInUrb->transfer_flags &= ~URB_ASYNC_UNLINK;
#endif
    usb_kill_urb(osdev->RegInUrb);
}

uint32_t athLnxUsbSubmitIntUrb(urb_t *urb, struct usb_device *usb, uint16_t epnum, uint16_t direction,
        struct sk_buff *buf, int buffer_length, usb_complete_t complete, void *context,
        uint32_t interval)
{
	uint32_t ret;


    if(direction == USB_DIR_OUT)
    {
		void *transfer_buffer = (void*) buf;

#ifdef ZM_USB_WAR_EP3_INTTOBULK
        usb_fill_bulk_urb(urb, usb, usb_sndbulkpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context);                
#else
        usb_fill_int_urb(urb, usb, usb_sndintpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context, interval);                
#endif
    }
    else
    {
        void *transfer_buffer = (void *)skb_put((struct sk_buff *)buf, ZM_USB_REG_MAX_BUF_SIZE);        

#ifdef ZM_USB_WAR_EP3_INTTOBULK
        usb_fill_bulk_urb(urb, usb, usb_rcvbulkpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context);                
#else
#ifdef ZM_USB_WAR_EP_INTTOBULK        
        usb_fill_int_urb(urb, usb, usb_rcvbulkpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context, interval);
#else
        usb_fill_int_urb(urb, usb, usb_rcvintpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context, interval);
#endif
#endif
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
    urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
    ret = usb_submit_urb(urb, GFP_ATOMIC);
#else
    ret = usb_submit_urb(urb);
#endif

    return ret;
}

uint32_t athLnxSubmitRegInUrb(osdev_t osdev);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) || \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
void athLnxUsbRegIn_callback(urb_t *urb)
#else
void athLnxUsbRegIn_callback(urb_t *urb, struct pt_regs *regs)
#endif
{
    int status;
    osdev_t osdev = (osdev_t)urb->context;

    /* Check status for URB */
    if (urb->status != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: status=0x%x\n", __func__, urb->status);
        if ((urb->status != -ENOENT) && (urb->status != -ECONNRESET)
            && (urb->status != -ESHUTDOWN))
        {
            #if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))    
                if (urb->status == USB_ST_INTERNALERROR)
                    status = -1;
            #else
                if (urb->status == -EPIPE){
                    /*printk(KERN_ERR "nonzero read bulk status received: -EPIPE");*/
                    status = -1;
                }

                if (urb->status == -EPROTO){
                    /*printk(KERN_ERR "nonzero read bulk status received: -EPROTO");*/
                    status = -1;
                }
            #endif
        }

        /* When FW recover is on going, we don't need to reissue URB */
        if (osdev->enablFwRcv == 1) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s free rx urb buffer\n", __func__);

            dev_kfree_skb_any(osdev->regUsbReadBuf);
            osdev->regUsbReadBuf = NULL;
            return;
        }

        if (urb->status != -ECONNRESET) {
             if ((urb->status == -EPROTO) ||
                 (urb->status == -ETIMEDOUT)) {
                if (osdev->RegInFailCnt < ZM_MAX_USB_URB_FAIL_COUNT) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "athLnxUsbRegIn_callback() : re-submit\n");
                    osdev->RegInFailCnt++;

          			#ifdef NBUF_PREALLOC_POOL
                    osdev->regUsbReadBuf->data = osdev->regUsbReadBuf->head;
                    osdev->regUsbReadBuf->tail = osdev->regUsbReadBuf->head;
                    osdev->regUsbReadBuf->len = 0;
                #else
                    dev_kfree_skb_any(osdev->regUsbReadBuf);
                    osdev->regUsbReadBuf = NULL;
                #endif
                    athLnxSubmitRegInUrb(osdev);
                    return;
                } 
                else {
                    HIF_Usb_Stop_Callback(osdev->host_hif_handle, osdev->host_wmi_handle, 1);
                }
             }
             else {
                if (urb->status == -ESHUTDOWN) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: stop submit urb, because of shutdown\n", __func__);
                    HIF_Usb_Stop_Callback(osdev->host_hif_handle, osdev->host_wmi_handle, 1);
                }
                else {
                     /* Re-Submit a Rx urb */
                     QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "athLnxUsbRegIn_callback() : re-submit\n");
                     osdev->RegInFailCnt = 0;

               	#ifdef NBUF_PREALLOC_POOL
                    osdev->regUsbReadBuf->data = osdev->regUsbReadBuf->head;
                    osdev->regUsbReadBuf->tail = osdev->regUsbReadBuf->head;
                    osdev->regUsbReadBuf->len = 0;
                #else        
                     dev_kfree_skb_any(osdev->regUsbReadBuf);
                     osdev->regUsbReadBuf = NULL;
                #endif

                     /* Issue another USB IN URB */
                     athLnxSubmitRegInUrb(osdev);
                     return;
                }
             }
        }

        #ifndef NBUF_PREALLOC_POOL
        dev_kfree_skb_any(osdev->regUsbReadBuf);
        osdev->regUsbReadBuf = NULL;
        #endif
        return;
    }

    if (urb->actual_length == 0)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "Get an URB whose length is zero");
        status = -1;
    }

    /* Set skb buffer length */
    #ifdef NET_SKBUFF_DATA_USES_OFFSET
        osdev->regUsbReadBuf->tail = 0;
        osdev->regUsbReadBuf->len = 0;
    #else
        osdev->regUsbReadBuf->tail = osdev->regUsbReadBuf->data;
        osdev->regUsbReadBuf->len = 0;
    #endif

    skb_put(osdev->regUsbReadBuf, urb->actual_length);
    
    HIF_UsbMsgIn_Callback(osdev->host_hif_handle, (void*)osdev->regUsbReadBuf);

#ifdef NBUF_PREALLOC_POOL
    osdev->regUsbReadBuf->data = osdev->regUsbReadBuf->head;
    osdev->regUsbReadBuf->tail = osdev->regUsbReadBuf->head;
    osdev->regUsbReadBuf->len = 0;
#else
    osdev->regUsbReadBuf = NULL;
#endif
    osdev->RegInFailCnt = 0;
    /* Issue another USB IN URB */
    athLnxSubmitRegInUrb(osdev);
}

uint32_t athLnxSubmitRegInUrb(osdev_t osdev)
{
#ifdef NBUF_PREALLOC_POOL
    uint32_t ret;
    
    ret = athLnxUsbSubmitIntUrb(osdev->RegInUrb, osdev->udev,
            USB_REG_IN_PIPE, USB_DIR_IN, (void*)osdev->regUsbReadBuf,
            ZM_USB_REG_MAX_BUF_SIZE, (usb_complete_t)athLnxUsbRegIn_callback, (void *)osdev, 1);

    return ret; 
#else    
    uint32_t ret;
    
    osdev->regUsbReadBuf = hif_usb_alloc_skb(ZM_USB_REG_MAX_BUF_SIZE, 0, 0);

    if (osdev->regUsbReadBuf != NULL)
    {
        ret = athLnxUsbSubmitIntUrb(osdev->RegInUrb, osdev->udev,
                USB_REG_IN_PIPE, USB_DIR_IN, (void*)osdev->regUsbReadBuf,
                ZM_USB_REG_MAX_BUF_SIZE, (usb_complete_t)athLnxUsbRegIn_callback, (void *)osdev, 1);
    }
    else
    {
        if (osdev->tm_rxbuf_act == 0)
        {
            osdev->tm_rxbuf_act = 1;

            //qdf_timer_start(&osdev->tm_rxbuf_alloc, RX_URB_BUF_ALLOC_TIMER);
            osdev->tm_rxbuf_alloc.expires = jiffies + msecs_to_jiffies(ZM_RX_URB_BUF_ALLOC_TIMER);
            add_timer(&osdev->tm_rxbuf_alloc);
        }

        return 1;
    }

    return ret;
#endif    
}

uint32_t athLnxUsbSubmitBulkUrb(urb_t *urb, struct usb_device *usb, uint16_t epnum, uint16_t direction,
      uint8_t *transfer_buffer, int buffer_length, usb_complete_t complete, void *context)
{
	uint32_t ret;

    if(direction == USB_DIR_OUT) {
        usb_fill_bulk_urb(urb, usb, usb_sndbulkpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context);

//        urb->transfer_flags |= URB_ZERO_PACKET;
    }
    else
        usb_fill_bulk_urb(urb, usb, usb_rcvbulkpipe(usb, epnum),
                transfer_buffer, buffer_length, complete, context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
    urb->transfer_flags |= URB_ASYNC_UNLINK;
#endif

    if (epnum == 4)
    {
        if (urb->hcpriv)
        {
            //printk("CWY - urb->hcpriv set by unknown reason, reset it\n");
            //urb->hcpriv = 0;
        }
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
    ret = usb_submit_urb(urb, GFP_ATOMIC);
#else
    ret = usb_submit_urb(urb);
#endif
    if ((epnum == 4) & (ret != 0))
    {
        //printk("CWY - ret = %x\n", ret);
    }
    return ret;
}

UsbUrbContext_t* athLnxAllocCmdUrbCtx(osdev_t osdev)
{
    int i;
    unsigned long irqFlag;
    UsbUrbContext_t *ctx = NULL;
                
    spin_lock_irqsave(&(osdev->CmdUrbLock), irqFlag);
    
    for ( i = 0; i < MAX_CMD_URB; i++ ) {
        if ( osdev->UsbCmdOutCtxs[i].inUse == 0 ) {
            ctx = &osdev->UsbCmdOutCtxs[i];
            ctx->inUse = 1;
            ctx->flags = 0;
            break;
        }
    }
    
    spin_unlock_irqrestore(&(osdev->CmdUrbLock), irqFlag);
    return ctx;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) || \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
void athLnxUsbRegOut_callback(urb_t *urb)
#else
void athLnxUsbRegOut_callback(urb_t *urb, struct pt_regs *regs)
#endif
{    	
    unsigned long irqFlag;
    UsbUrbContext_t *ctx = (UsbUrbContext_t *)urb->context;
    osdev_t osdev = (osdev_t)ctx->osdev;
    struct sk_buff *buf;
            
    spin_lock_irqsave(&(osdev->CmdUrbLock), irqFlag);
    buf = ctx->buf;
    ctx->inUse = 0;
    ctx->buf = NULL;
    spin_unlock_irqrestore(&(osdev->CmdUrbLock), irqFlag);

    if (ctx->flags == 0)
        HIF_UsbCmdOut_Callback(osdev->host_hif_handle, buf);  	
    else
        dev_kfree_skb_any(buf);

    ctx->flags = 0;
}

struct sk_buff * athLnxGetUsbRxBuffer(osdev_t osdev)
{
    struct sk_buff * buf;
    unsigned long irqFlag;    
    
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);

    if (osdev->RxBufCnt != 0)
    {
        buf = osdev->UsbRxBufQ[osdev->RxBufHead];
        osdev->RxBufHead = ((osdev->RxBufHead+1) & (ZM_MAX_RX_URB_NUM - 1));
        osdev->RxBufCnt--;
    }
    else
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "RxBufQ inconsistent: RxBufHead: %d, RxBufTail: %d\n",
                osdev->RxBufHead, osdev->RxBufTail);
        spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
        return NULL;
    }

    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return buf;
}

uint32_t athLnxPutUsbRxBuffer(osdev_t osdev, struct sk_buff * buf)
{
    uint16_t idx;
    unsigned long irqFlag;    
    
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);

    idx = ((osdev->RxBufTail+1) & (ZM_MAX_RX_URB_NUM - 1));

    if (osdev->RxBufCnt != ZM_MAX_RX_URB_NUM)
    {
        osdev->UsbRxBufQ[osdev->RxBufTail] = buf;
        osdev->RxBufTail = idx;
        osdev->RxBufCnt++;
    }
    else
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "RxBufQ inconsistent: RxBufHead: %d, RxBufTail: %d\n",
                osdev->RxBufHead, osdev->RxBufTail);
        spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
        return 0xffff;
    }

    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return 0;
}

uint32_t athLnxUsbIn(osdev_t osdev, UsbRxUrbContext *RxUrbCtx)
{
    uint32_t ret;
    urb_t *urb = RxUrbCtx->WlanRxDataUrb;

    /* Submit a rx urb */
    ret = athLnxUsbSubmitBulkUrb(urb, osdev->udev, USB_WLAN_RX_PIPE,
            USB_DIR_IN, RxUrbCtx->rxUsbBuf, ZM_MAX_RX_BUFFER_SIZE,
            (usb_complete_t)athLnxUsbDataIn_callback, (void *)RxUrbCtx);

    //CWYang(-)
    //if (ret != 0)
    //    printk(KERN_ERR "athLnxUsbSubmitBulkUrb fail, status: 0x%08x\n", (int)ret);

    return ret;
}

void athLnxRxUrbBufTimer(unsigned long param)
{
    osdev_t osdev = (osdev_t) param;
    uint16_t i;
    uint8_t timer_act = 0;

#ifndef NBUF_PREALLOC_POOL
    if (osdev->regUsbReadBuf == NULL)
    {
        osdev->regUsbReadBuf = hif_usb_alloc_skb(ZM_USB_REG_MAX_BUF_SIZE, 0, 0);

        if (osdev->regUsbReadBuf)
        {
            athLnxUsbSubmitIntUrb(osdev->RegInUrb, osdev->udev,
                USB_REG_IN_PIPE, USB_DIR_IN, (void*)osdev->regUsbReadBuf,
                ZM_USB_REG_MAX_BUF_SIZE, (usb_complete_t)athLnxUsbRegIn_callback, (void *)osdev, 1);
        }
        else
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: REG_IN Buf alloc fail\n", __FUNCTION__);
            timer_act = 1;
            goto error;
        }
    }
#endif    

    for (i = 0; i < ZM_MAX_RX_URB_NUM; i++)
    {
        /* Check whether rx buffer allocation fail */
        if (osdev->RxUrbCtx[i].inUse == 0)
        {
            osdev->RxUrbCtx[i].buf = hif_usb_alloc_skb(ZM_MAX_RX_BUFFER_SIZE, 0, 0);

            if (osdev->RxUrbCtx[i].buf)
            {
                osdev->RxUrbCtx[i].inUse = 1;
                osdev->RxUrbCtx[i].failcnt = 0;
                osdev->RxUrbCtx[i].rxUsbBuf = osdev->RxUrbCtx[i].buf->data;
                athLnxUsbIn(osdev, &(osdev->RxUrbCtx[i]));
            }
            else
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: DATA_IN Buf alloc fail, index = %d\n", __FUNCTION__, i);
                timer_act = 1;
                break;
            }
        }
    }
#ifndef NBUF_PREALLOC_POOL
error:
#endif	

    /* Check whether we need to restart timer */
    if (timer_act)
    {
        osdev->tm_rxbuf_act = 1;
        //qdf_timer_start(&osdev->tm_rxbuf_alloc, RX_URB_BUF_ALLOC_TIMER);
        osdev->tm_rxbuf_alloc.expires = jiffies + msecs_to_jiffies(ZM_RX_URB_BUF_ALLOC_TIMER);
        add_timer(&osdev->tm_rxbuf_alloc);

    }
    else
    {
        osdev->tm_rxbuf_act = 0;
        //qdf_timer_stop(&osdev->tm_rxbuf_alloc);
        del_timer(&osdev->tm_rxbuf_alloc);
    }
}

void athLnxStartPerSecTimer(osdev_t osdev)
{
    init_timer(&osdev->one_sec_timer);
    osdev->one_sec_timer.function = athLnxPerSecTimer;
    osdev->one_sec_timer.data = (unsigned long)osdev;

    mod_timer(&(osdev->one_sec_timer), jiffies + HZ);
}

void athLnxStopPerSecTimer(osdev_t osdev)
{
    del_timer(&(osdev->one_sec_timer));
}

static void initTxPipe(HIFUSBTxPipe *pipe, int pipeNum)
{
    int ii;
    int max_tx_buf_size;

    /* Zero memory for UsbTxBufQ */    
    memset(pipe->UsbTxBufQ, 0, sizeof(UsbTxQ_t) * ZM_MAX_TX_URB_NUM);

    if (pipeNum == USB_WLAN_TX_PIPE)
        max_tx_buf_size = ZM_USB_TX_BUF_SIZE;
    else
        max_tx_buf_size = 2048;
 
    for (ii = 0; ii < ZM_MAX_TX_URB_NUM; ii++)
        pipe->TxUrbCtx[ii].txUsbBuf = kmalloc(max_tx_buf_size, GFP_ATOMIC);

    pipe->TxBufHead = 0;
    pipe->TxBufTail = 0;
    pipe->TxUrbHead = 0;
    pipe->TxUrbTail = 0;
    pipe->TxUrbCnt = ZM_MAX_TX_URB_NUM;
    pipe->TxPipeNum = pipeNum;
}

void athLnxInitUsbTxQ(osdev_t osdev)
{
    initTxPipe(&osdev->TxPipe, USB_WLAN_TX_PIPE);
    initTxPipe(&osdev->HPTxPipe, USB_WLAN_HP_TX_PIPE);
//    initTxPipe(&osdev->MPTxPipe, USB_WLAN_MP_TX_PIPE);

    osdev->TxPipe.TxUrbCompleteCb = (usb_complete_t)athLnxUsbDataOut_callback;
    osdev->HPTxPipe.TxUrbCompleteCb = (usb_complete_t)athLnxUsbDataOut_callback;
//    osdev->MPTxPipe.TxUrbCompleteCb = (usb_complete_t)athLnxUsbDataOut_callback;    
}

void athLnxInitUsbRxQ(osdev_t osdev)
{
    uint16_t i;
    struct sk_buff* buf;

    /* Zero memory for UsbRxBufQ */
    //memset(osdev->UsbRxBufQ, 0, sizeof(struct sk_buff *) * ZM_MAX_RX_URB_NUM);

    /* Initialize rx buffer reallocation timer */
    init_timer(&osdev->tm_rxbuf_alloc);
    osdev->tm_rxbuf_alloc.function = athLnxRxUrbBufTimer;
    osdev->tm_rxbuf_alloc.data = (unsigned long)osdev;

    osdev->RxBufHead = 0;

    /* Submit all Rx urbs */
    for (i = 0; i < ZM_MAX_RX_URB_NUM; i++)
    {
        buf =  hif_usb_alloc_skb(ZM_MAX_RX_BUFFER_SIZE, 0, 0); 
        osdev->RxUrbCtx[i].buf = buf;
        osdev->RxUrbCtx[i].osdev = osdev;
        osdev->RxUrbCtx[i].inUse = 1;
        osdev->RxUrbCtx[i].failcnt = 0;
        osdev->RxUrbCtx[i].rxUsbBuf = buf->data;
        athLnxUsbIn(osdev, &(osdev->RxUrbCtx[i]));
    }
}



#define IEEE80211_CRC_LEN       4
#define IEEE80211_WEP_IVLEN     3
#define IEEE80211_WEP_KIDLEN    1
#define IEEE80211_WEP_CRCLEN    4

#define IEEE80211_MAX_MPDU_LEN      (3840 + IEEE80211_CRC_LEN + \
    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + IEEE80211_WEP_CRCLEN))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))||(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
void athLnxUsbDataIn_callback(urb_t *urb)
#else
void athLnxUsbDataIn_callback(urb_t *urb, struct pt_regs *regs)
#endif
{
    UsbRxUrbContext *RxUrbCtx = (UsbRxUrbContext *)urb->context;
    osdev_t osdev = RxUrbCtx->osdev;

    u_int8_t *data = RxUrbCtx->rxUsbBuf;
    int status;

#if ZM_USB_STREAM_MODE == 1
    int index = 0;
    u_int16_t pkt_len;
    u_int16_t pkt_tag;
    u_int16_t ii;
    struct sk_buff * buf = NULL;
    struct sk_buff * rxBufPool[ZM_MAX_USB_IN_NUM];
    ath_usb_rx_info_t rx_info[ZM_MAX_USB_IN_NUM];
    u_int16_t rxBufPoolIndex = 0;
    int remain_len = 0;
    int check_pad = 0;
    int check_len = 0;
    u_int16_t packet_over_trans = 0;
#endif

    /* Check status for URB */
    if (urb->status != 0){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxUsbDataIn_callback() : status=0x%x\n", urb->status);
        if ((urb->status != -ENOENT) && (urb->status != -ECONNRESET)
            && (urb->status != -ESHUTDOWN))
        {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))    
                if (urb->status == USB_ST_INTERNALERROR)
                    status = -1;
#else
                if (urb->status == -EPIPE){
                    /*printk(KERN_ERR "nonzero read bulk status received: -EPIPE");*/
                    status = -1;
                }

                if (urb->status == -EPROTO){
                    /*printk(KERN_ERR "nonzero read bulk status received: -EPROTO");*/
                    status = -1;
                }
#endif
        }

        /* When FW recover is on going, we don't need to reissue URB */
        if (osdev->enablFwRcv == 1) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s free rx urb buffer\n", __func__);

            RxUrbCtx->inUse = 0;
            buf = RxUrbCtx->buf;
            RxUrbCtx->buf = NULL;
            dev_kfree_skb_any(buf);

            return;
        }

        if (urb->status != -ECONNRESET) {
             if ((urb->status == -EPROTO) ||
                 (urb->status == -ETIMEDOUT)) {
                if (RxUrbCtx->failcnt < ZM_MAX_USB_URB_FAIL_COUNT) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "zfLnxUsbDataIn_callback() : re-submit\n");
                    RxUrbCtx->failcnt ++;
                    athLnxUsbIn(osdev, RxUrbCtx);
                    return;
                } 
                else {
                    HIF_Usb_Stop_Callback(osdev->host_hif_handle, osdev->host_wmi_handle, 1);
                }
             }
             else {
                if (urb->status == -ESHUTDOWN) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: stop submit urb, because of shutdown\n", __func__);
                    HIF_Usb_Stop_Callback(osdev->host_hif_handle, osdev->host_wmi_handle, 1);
                }
                else {
                     /* Re-Submit a Rx urb */
                     QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "zfLnxUsbDataIn_callback() : re-submit\n");
                     RxUrbCtx->failcnt = 0;
                     athLnxUsbIn(osdev, RxUrbCtx);
                     return;
                }
             }
        }

        RxUrbCtx->inUse = 0;
        buf = RxUrbCtx->buf;
        RxUrbCtx->buf = NULL;
        dev_kfree_skb_any(buf);

        return;
    }

    if (urb->actual_length == 0)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "Get an URB whose length is zero\n");

        /* Resumit URB */
        athLnxUsbIn(osdev, RxUrbCtx);
        return;
    }

    /* Dequeue skb buffer */
    RxUrbCtx->failcnt = 0;

#if ZM_USB_STREAM_MODE == 1
    remain_len = osdev->remain_len;
    check_pad = osdev->check_pad;
    check_len = osdev->check_len;

    if (remain_len != 0)
    {
        struct sk_buff* remain_buf = osdev->remain_buf;

        /* move index to the offset contains the next packet */
        index = remain_len;
        remain_len -= check_pad;

        /* If there is no enough room for the data */
        if ((remain_len + check_len) > remain_buf->len) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: not enough space in the remain buffer, len: %d, remain_len: %d, check_len: %d\n",
                    __func__, remain_buf->len, remain_len, check_len);

            /* set remain_buf len to 0 */
            osdev->remain_len = 0;
            dev_kfree_skb_any(remain_buf);
        }
        else {

            /*  Copy data */
            memcpy(&(remain_buf->data[check_len]), data, remain_len);

            /* set remain_buf len to 0 */
            osdev->remain_len = 0;

            packet_over_trans = 1;
            rxBufPool[rxBufPoolIndex++] = remain_buf;
        }
    }

    /* Peek the USB transfers */
    while(index < urb->actual_length)
    {
        pkt_len = data[index] + (data[index+1] << 8);
        pkt_tag = data[index+2] + (data[index+3] << 8);

        if (pkt_len > IEEE80211_MAX_MPDU_LEN)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s get error packet length = %d\n", __FUNCTION__, pkt_len);
            break;
        }

        if (pkt_tag == ATH_USB_STREAM_MODE_TAG)
        {
            int pad_len;
            int prev_pkt_offset;

            rx_info[rxBufPoolIndex].pkt_len = pkt_len;
            rx_info[rxBufPoolIndex].offset = index+4;
            rxBufPoolIndex++;

            pad_len = 4 - (pkt_len & 0x3);

            if(pad_len == 4)
                pad_len = 0;

            prev_pkt_offset = index;
            index = index + 4 + pkt_len + pad_len;

            if (index > ZM_MAX_RX_BUFFER_SIZE)
            {
                struct sk_buff* new_buf;

                osdev->remain_len = index - ZM_MAX_RX_BUFFER_SIZE;
                osdev->check_len = ZM_MAX_RX_BUFFER_SIZE - prev_pkt_offset - 4;
                osdev->check_pad = pad_len;

                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: Frame is transmitted in the next Transfer\n", __func__);

                /* allocate a new buffer */
                new_buf = dev_alloc_skb(pkt_len);

                /* Set skb buffer length */
            #ifdef NET_SKBUFF_DATA_USES_OFFSET
                new_buf->tail = 0;
                new_buf->len = 0;
            #else
                new_buf->tail = new_buf->data;
                new_buf->len = 0;
            #endif

                skb_put(new_buf, pkt_len);

                /* The length we want to copy is larger than the buffer we allocate */
                if (osdev->check_len > pkt_len) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: copy too many bytes, check_len: %d, pkt_len: %d\n",
                            __func__, osdev->check_len, pkt_len);

                    rxBufPoolIndex--;
                    osdev->remain_len = 0;
                    osdev->remain_buf = NULL;

                    dev_kfree_skb_any(new_buf);
                    break;
                }

                /* Copy the buffer */
                memcpy(new_buf->data, &(data[prev_pkt_offset+4]), osdev->check_len);

                /* Record the buffer pointer */
                osdev->remain_buf = new_buf;

                /* compenstate the buffer index */
                rxBufPoolIndex--;
                break;
            }            
        }
        else
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "Can't find tag, pkt_len: 0x%04x, tag: 0x%04x  rxBufPoolIndex: %d\n", pkt_len, pkt_tag, rxBufPoolIndex);
            break;
        }
    }

#if 0 /* remove the zero copy mechanism if only one packet in the USB transfer */
    if (rxBufPoolIndex == 1)
    {
        /* Skip 4 bytes USB Tag */
        RxUrbCtx->buf->data += 4;

        /* Set skb buffer length */
    #ifdef NET_SKBUFF_DATA_USES_OFFSET
        RxUrbCtx->buf->tail = 0;
        RxUrbCtx->buf->len = 0;
    #else
        RxUrbCtx->buf->tail = RxUrbCtx->buf->data;
        RxUrbCtx->buf->len = 0;
    #endif

        skb_put(RxUrbCtx->buf, rx_info[0].pkt_len);

        rxBufPool[0] = RxUrbCtx->buf;

		buf = hif_usb_alloc_skb(ZM_MAX_RX_BUFFER_SIZE, 0, 0);

        /* If we can't allocate buf successfully */
        if (buf == NULL)
        {
            RxUrbCtx->inUse = 0;
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_DEBUG "%s: can't allocate rx buffer, start rx buf timer\n", __func__);

            if (!osdev->tm_rxbuf_act)
            {
                osdev->tm_rxbuf_act = 1;
                osdev->tm_rxbuf_alloc.expires = jiffies + msecs_to_jiffies(ZM_RX_URB_BUF_ALLOC_TIMER);
                add_timer(&osdev->tm_rxbuf_alloc);
            }

            goto alloc_fail;
        }
        else
        {
            RxUrbCtx->buf = buf;
            RxUrbCtx->rxUsbBuf = buf->data;
        }
    }
    else
#endif
    {
        struct sk_buff * new_buf = NULL;

        for(ii = packet_over_trans; ii < rxBufPoolIndex; ii++)
        {
            u_int16_t len = rx_info[ii].pkt_len;
            int offset = rx_info[ii].offset;

    #ifndef ZM_DONT_COPY_RX_BUFFER
            new_buf = dev_alloc_skb(len);
    #else
            new_buf = skb_clone(RxUrbCtx->buf, GFP_ATOMIC);
    #endif

            /* If we can't allocate buffer successfully, stop allocate */
            if (new_buf == NULL)
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_DEBUG "%s: can't allocate rx buffer\n", __func__);

                rxBufPoolIndex = ii;
                break;
            }

    #ifndef ZM_DONT_COPY_RX_BUFFER
            /* Set skb buffer length */
            #ifdef NET_SKBUFF_DATA_USES_OFFSET
                new_buf->tail = 0;
                new_buf->len = 0;
            #else
                new_buf->tail = new_buf->data;
                new_buf->len = 0;
            #endif

            skb_put(new_buf, len);

            /* Copy the buffer */
            memcpy(new_buf->data, &(data[offset]), len);
    #else
            new_buf->data = &(data[offset]);
            new_buf->len = len;
    #endif
            rxBufPool[ii] = new_buf;
        }
    }

#ifdef ZM_DONT_COPY_RX_BUFFER
    dev_kfree_skb_any(RxUrbCtx->buf);

    buf = hif_usb_alloc_skb(ZM_MAX_RX_BUFFER_SIZE, 0, 0);

    /* If we can't allocate buf successfully */
    if (buf == NULL)
    {
        RxUrbCtx->inUse = 0;
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_DEBUG "%s: can't allocate rx buffer, start rx buf timer\n", __func__);

        if (!osdev->tm_rxbuf_act)
        {
            osdev->tm_rxbuf_act = 1;
            osdev->tm_rxbuf_alloc.expires = jiffies + msecs_to_jiffies(ZM_RX_URB_BUF_ALLOC_TIMER);
            add_timer(&osdev->tm_rxbuf_alloc);
        }

        goto alloc_fail;
    }
    else
    {
        RxUrbCtx->buf = buf;
        RxUrbCtx->rxUsbBuf = buf->data;
    }
#endif /* #ifdef ZM_DONT_COPY_RX_BUFFER */
#endif /* #if ZM_USB_STREAM_MODE == 1 */

    /* Submit IN URB */
    athLnxUsbIn(osdev, RxUrbCtx);

//alloc_fail:

#if ZM_USB_STREAM_MODE == 1
    /* pass data to upper layer */
    for(ii = 0; ii < rxBufPoolIndex; ii++)
    {
        HIF_UsbDataIn_Callback(osdev->host_hif_handle, (void *)rxBufPool[ii]);
    }
#else
    /* pass data to upper layer */
    HIF_UsbDataIn_Callback(osdev->host_hif_handle, (void *)buf);
#endif
}

UsbTxUrbContext* athLnxGetFreeTxUrb(osdev_t osdev,  HIFUSBTxPipe *pipe)
{
    uint16_t idx;
    unsigned long irqFlag;
    UsbTxUrbContext *ctx = NULL;
        
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);
#if 0
    //idx = ((osdev->TxUrbTail + 1) & (ZM_MAX_TX_URB_NUM - 1));

    //if (idx != osdev->TxUrbHead)
    if (pipe->TxUrbCnt != 0)
    {
        idx = pipe->TxUrbTail;
        pipe->TxUrbTail = ((pipe->TxUrbTail + 1) & (ZM_MAX_TX_URB_NUM - 1));
        pipe->TxUrbCnt--;        
    }
    else
    {   
        //printk(KERN_ERR "osdev->TxUrbCnt: %d\n", pipe->TxUrbCnt); 
        idx = 0xffff;
    }
#else
    for(idx=0; idx<ZM_MAX_TX_URB_NUM; idx++) {
        if ( pipe->TxUrbCtx[idx].inUse == 0 ) {
            pipe->TxUrbCtx[idx].inUse = 1;
            ctx = &pipe->TxUrbCtx[idx];            
            break;
        }
    }
#endif

    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return ctx;
}

void athLnxPutTxUrb(osdev_t osdev, HIFUSBTxPipe *pipe, UsbTxUrbContext *ctx)
{
    unsigned long irqFlag;
        
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);
#if 0
    idx = ((pipe->TxUrbHead + 1) & (ZM_MAX_TX_URB_NUM - 1));

    //if (idx != macp->TxUrbTail)
    if (pipe->TxUrbCnt < ZM_MAX_TX_URB_NUM)
    {
        pipe->TxUrbHead = idx;
        pipe->TxUrbCnt++;
    }
    else
    {    
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "UsbTxUrbQ inconsistent: TxUrbHead: %d, TxUrbTail: %d\n",
                osdev->TxUrbHead, osdev->TxUrbTail);
    }
#else
    ctx->inUse = 0;     
    ctx->delay_free = 0;
#endif

    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
}

uint16_t athLnxCheckTxBufferCnt(osdev_t osdev,  HIFUSBTxPipe *pipe, u_int32_t *timestamp)
{
    uint16_t TxBufCnt;
    unsigned long irqFlag;
    
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);
    TxBufCnt = pipe->TxBufCnt;

    if (TxBufCnt && timestamp) {
        UsbTxQ_t *TxQ;
        TxQ = (UsbTxQ_t *)&(pipe->UsbTxBufQ[pipe->TxBufHead]);
        *timestamp = TxQ->timeStamp;
    }
    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return TxBufCnt;
}

UsbTxQ_t *athLnxGetUsbTxBuffer(osdev_t osdev, HIFUSBTxPipe *pipe, UsbTxQ_t *TxQ)
{
    uint16_t idx;
    unsigned long irqFlag;    
    u_int16_t max_tx_buf_num = ((osdev->isMagpie == TRUE) ? ZM_MAX_TX_BUF_NUM : ZM_MAX_TX_BUF_NUM_K2); 
        
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);

    idx = ((pipe->TxBufHead+1) & (max_tx_buf_num - 1));

    //if (idx != osdev->TxBufTail)
    if (pipe->TxBufCnt > 0)
    {
#ifdef CONFIG_SMP
        /*
            Another CPU will overwrite the TxQ's content if this TxQ not yet processed completely.
            Hence, we clone the TxQ and return.
        */
        memcpy(TxQ, (void *)&(pipe->UsbTxBufQ[pipe->TxBufHead]), sizeof(UsbTxQ_t));
#else
        TxQ = (UsbTxQ_t *)&(pipe->UsbTxBufQ[pipe->TxBufHead]);
#endif
        pipe->TxBufHead = ((pipe->TxBufHead+1) & (max_tx_buf_num - 1));
        pipe->TxBufCnt--;
    }
    else
    {
        if (pipe->TxBufHead != pipe->TxBufTail)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxGetUsbTxBuffer UsbTxBufQ inconsistent: \
								TxBufHead: %d, TxBufTail: %d\n", pipe->TxBufHead, 
							pipe->TxBufTail);
        }

        spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
        return NULL;
    }

    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return TxQ;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
void athLnxUsbDataOut_callback(urb_t *urb)
#else
void athLnxUsbDataOut_callback(urb_t *urb, struct pt_regs *regs)
#endif
{
    UsbTxUrbContext *ctx = (UsbTxUrbContext *)urb->context;
    osdev_t osdev = ctx->osdev;

    if (ctx->delay_free == 1)
    {
        /* Because the buf contains USB Tx tag, we need to revert the header */
        skb_pull(ctx->buf, 4);
        dev_kfree_skb_any(ctx->buf);
        ctx->buf = NULL;
    }

    /* Give the urb back */
    athLnxPutTxUrb(osdev, (HIFUSBTxPipe *)ctx->pipe, ctx);

    /* Check whether there is any pending buffer needed */
    /* to be sent */
    if (athLnxCheckTxBufferCnt(osdev, (HIFUSBTxPipe *)ctx->pipe, NULL) != 0)
    {
        athLnxUsbSubmitTxData(osdev, (HIFUSBTxPipe *)ctx->pipe);
    }

    /* callback move to submitTxData */
    //HIF_UsbDataOut_Callback(osdev->host_hif_handle, buf);
}

uint32_t athLnxUsbSubmitTxData_NONDATA(osdev_t osdev, HIFUSBTxPipe *pipe)
{
    uint32_t ret;
    UsbTxUrbContext* freeTxUrb = NULL;
    uint8_t *puTxBuf = NULL;
    UsbTxQ_t  *TxData, TxQ;
    uint8_t *transfer_buffer;
    uint32_t len;

    /* First check whether there is a free URB */
    freeTxUrb = athLnxGetFreeTxUrb(osdev, pipe);

    /* If there is no any free Tx Urb */
    if (freeTxUrb == NULL)
    {   
        //printk("CWY - Can't get free Tx Urb\n");
        return 0xffff;
    }

    /* Dequeue the packet from UsbTxBufQ */
    TxData = athLnxGetUsbTxBuffer(osdev, pipe, &TxQ);
    if (TxData == NULL)
    {
        /* Give the urb back */
        athLnxPutTxUrb(osdev, pipe, freeTxUrb);
        return 0xffff;
    }

    /* Point to the freeTxUrb buffer */
    puTxBuf = freeTxUrb->txUsbBuf;

	transfer_buffer = TxData->buf->data;
	len = TxData->buf->len;

    

    memcpy(puTxBuf, transfer_buffer, len);   

    /* Submit a tx urb */
//    ret = athLnxUsbSubmitBulkUrb(osdev->WlanTxDataUrb[freeTxUrb], osdev->udev,
//            USB_WLAN_TX_PIPE, USB_DIR_OUT, osdev->txUsbBuf[freeTxUrb],
//            len, (usb_complete_t)athLnxUsbDataOut_callback, osdev);   
    ret = athLnxUsbSubmitBulkUrb(freeTxUrb->urb, osdev->udev,
            pipe->TxPipeNum, USB_DIR_OUT, freeTxUrb->txUsbBuf,
            len, pipe->TxUrbCompleteCb, (void *)freeTxUrb);                

    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxUsbSubmitBulkUrb fail, status: 0x%08x\n", (int)ret);
        /* Give the urb back */
        athLnxPutTxUrb(osdev, pipe, freeTxUrb);
    }

    /* free packet */
    dev_kfree_skb_any(TxData->buf);

    return ret;
}

uint32_t athLnxUsbSubmitTxData(osdev_t osdev, HIFUSBTxPipe *pipe)
{
    uint32_t ret = 0;
    UsbTxUrbContext* freeTxUrb = NULL;
    uint8_t *puTxBuf = NULL;
    UsbTxQ_t *TxData, TxQ;
#if ZM_USB_TX_STREAM_MODE == 1
    uint8_t               ii;
    uint16_t              offset = 0;
    uint16_t              usbTxAggCnt;
    uint16_t              *pUsbTxHdr;
    struct sk_buff          *SkbPool[ZM_MAX_TX_AGGREGATE_NUM];
    u_int32_t               timeStamp = 0;
#endif
    uint8_t *transfer_buffer;
    uint32_t len = 0;

    /* When FW recover is on going, block Tx transmission */
    if (osdev->enablFwRcv == 1) {
        return 0xffff;
    }

#if ZM_USB_TX_STREAM_MODE == 1
    if (pipe->TxPipeNum != 1)
#endif
        return athLnxUsbSubmitTxData_NONDATA(osdev, pipe);

    /* First check whether there is a free URB */
    freeTxUrb = athLnxGetFreeTxUrb(osdev, pipe);

    /* If there is no any free Tx Urb */
    if (freeTxUrb == NULL)
    {   
        //printk("CWY - Can't get free Tx Urb(%d)\n", pipe->TxPipeNum);
        return 0xffff;
    }

#if ZM_USB_TX_STREAM_MODE == 1
    usbTxAggCnt = athLnxCheckTxBufferCnt(osdev, pipe, &timeStamp);

    if (usbTxAggCnt >= ZM_MAX_TX_AGGREGATE_NUM)
    {
       usbTxAggCnt = ZM_MAX_TX_AGGREGATE_NUM;
    }
    else if (usbTxAggCnt == 0)
    {
        /* Give the urb back */
        athLnxPutTxUrb(osdev, pipe, freeTxUrb);
        return 0xffff;
    }
    else if ((atomic_read(&(osdev->txFrameNumPerSecond)) > ZM_L1_TX_PACKET_THR) &&
             (usbTxAggCnt < ZM_L1_TX_AGGREGATE_NUM) &&
             (timeStamp == A_MS_TICKGET()))
    {
        /* Give the urb back */
        athLnxPutTxUrb(osdev, pipe, freeTxUrb);
        return 0xffff;
    }

#endif

#if ZM_USB_TX_STREAM_MODE == 1
    /* If there is only one packet, we don't need to copy the buffer */
    if (usbTxAggCnt == 1)
    {
        TxData = athLnxGetUsbTxBuffer(osdev, pipe, &TxQ);
        if (TxData == NULL)
        {
            /* Give the urb back */
            athLnxPutTxUrb(osdev, pipe, freeTxUrb);
            return 0xffff;
        }

        /* Check the header room */
        if (skb_headroom(TxData->buf) < 4)
        {
            struct sk_buff *new_buf = NULL;

            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: header room is not enough\n", __func__);

            /* realloc the skb to make sure there is at least 4 bytes headroom */
            skb_unshare(TxData->buf, GFP_ATOMIC);
            new_buf = skb_realloc_headroom(TxData->buf, 4);

            if (new_buf == NULL)
            {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: skb_realloc_headroom fail\n", __func__);

                /* currently we drop the tranmission of this packet */
                dev_kfree_skb_any(TxData->buf);
                TxData->buf = NULL;

                /* Give the urb back */
                athLnxPutTxUrb(osdev, pipe, freeTxUrb);
                return 0xffff;
            }

            dev_kfree_skb_any(TxData->buf);
            TxData->buf = new_buf;
        }

        skb_push(TxData->buf, 4);

        pUsbTxHdr = (uint16_t *)TxData->buf->data;

        *pUsbTxHdr++ = htole16(TxData->hdrlen + TxData->snapLen + 
                               (TxData->buf->len - TxData->offset - 4) +  TxData->tailLen);

        *pUsbTxHdr++ = htole16(0x697e);

		transfer_buffer = TxData->buf->data;

        /* Check whether the address is 2 bytes aligment */
        if (((u_int32_t)transfer_buffer & 0x1) != 0)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_EMERG "%s: buffer is not 2 byte alignment\n", __func__);
            BUG();
        }

		len = TxData->buf->len;

        freeTxUrb->delay_free = 1;
        freeTxUrb->buf = TxData->buf;

        /* Submit a tx urb */
        ret = athLnxUsbSubmitBulkUrb(freeTxUrb->urb, osdev->udev,
                pipe->TxPipeNum, USB_DIR_OUT, TxData->buf->data,
                len, pipe->TxUrbCompleteCb, (void *)freeTxUrb);
    }
    else
    {
        for(ii = 0; ii < usbTxAggCnt; ii++)
        {
#endif
            /* Dequeue the packet from UsbTxBufQ */
            TxData = athLnxGetUsbTxBuffer(osdev, pipe, &TxQ);
            if (TxData == NULL)
            {
                usbTxAggCnt = ii;
                break;
            }
            
            /* Point to the freeTxUrb buffer */
            puTxBuf = freeTxUrb->txUsbBuf;

#if ZM_USB_TX_STREAM_MODE == 1
            puTxBuf += offset;
            pUsbTxHdr = (uint16_t *)puTxBuf;
            
            /* Add the packet length and tag information */
            *pUsbTxHdr++ = htole16(TxData->hdrlen + TxData->snapLen + 
                                   (TxData->buf->len - TxData->offset) +  TxData->tailLen);
            
            *pUsbTxHdr++ = htole16(0x697e);
            
            puTxBuf += 4;
#endif // #ifdef ZM_USB_TX_STREAM_MODE

			transfer_buffer = TxData->buf->data;
			len =  TxData->buf->len;           

            memcpy(puTxBuf, transfer_buffer, len);

#if ZM_USB_TX_STREAM_MODE == 1
            // Add the Length and Tag
            len += 4;
            
            if (ii < (usbTxAggCnt-1))
            {
                /* Pad the buffer to firmware descriptor boundary */
                offset += (((len-1) >> 2) + 1) << 2;
            }
            
            if (ii == (usbTxAggCnt-1))
            {
                len += offset;
            }
            
//            pUsbTxHdr += len;
            SkbPool[ii] = TxData->buf;
        }

        freeTxUrb->delay_free = 0;

        if (usbTxAggCnt != 0) {
            /* Submit a tx urb */
            ret = athLnxUsbSubmitBulkUrb(freeTxUrb->urb, osdev->udev,
                    pipe->TxPipeNum, USB_DIR_OUT, freeTxUrb->txUsbBuf,
                    len, pipe->TxUrbCompleteCb, (void *)freeTxUrb);
        }
        else {
            return -EINVAL;
        }
    } /* if (usbTxAggCnt == 1) */

#endif

    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxUsbSubmitBulkUrb fail, status: 0x%08x\n", (int)ret);
        /* Give the urb back */
        athLnxPutTxUrb(osdev, pipe, freeTxUrb);
    }

    /* free packet */
#if ZM_USB_TX_STREAM_MODE == 1
    atomic_add(usbTxAggCnt, &osdev->txFrameCnt);

    if (usbTxAggCnt != 1) {
        for(ii = 0; ii < usbTxAggCnt; ii++) {
            dev_kfree_skb_any(SkbPool[ii]);
        }
    }
#else
    dev_kfree_skb_any(TxData->buf);
#endif

    return ret;
}

uint16_t athLnxPutUsbTxBuffer(osdev_t osdev, struct sk_buff * buf, HIFUSBTxPipe *pipe)
{
    uint16_t idx;
    UsbTxQ_t *TxQ;
    unsigned long irqFlag;    
    u_int16_t max_tx_buf_num = ((osdev->isMagpie == TRUE) ? ZM_MAX_TX_BUF_NUM : ZM_MAX_TX_BUF_NUM_K2);
        
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);

    idx = ((pipe->TxBufTail+1) & (max_tx_buf_num - 1));

    //if (idx != macp->TxBufHead)
    if (pipe->TxBufCnt < max_tx_buf_num)
    {
        TxQ = (UsbTxQ_t *)&(pipe->UsbTxBufQ[pipe->TxBufTail]);

        TxQ->buf = buf;
        TxQ->timeStamp = A_MS_TICKGET();

        pipe->TxBufTail = ((pipe->TxBufTail+1) & (max_tx_buf_num - 1));
        pipe->TxBufCnt++;
    }
    else
    {
#if 0
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxPutUsbTxBuffer UsbTxBufQ inconsistent: TxBufHead: %d, TxBufTail: %d, TxBufCnt: %d\n",
            pipe->TxBufHead, pipe->TxBufTail, pipe->TxBufCnt);
#endif
        spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
        return 0xffff;
    }

    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return 0;
}

uint32_t athLnxUsbOut(osdev_t osdev, struct sk_buff * buf, HIFUSBTxPipe *pipe)
{
    uint32_t ret = 0;

    /* Enqueue the packet into UsbTxBufQ */
    if (athLnxPutUsbTxBuffer(osdev, buf, pipe) == 0xffff)
    {
        /* free packet */
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxPutUsbTxBuffer Error!!\n");
        return 0xffff;
    }

    athLnxUsbSubmitTxData(osdev, pipe);
    return ret;
}

uint32_t athLnxUsbSubmitControl(osdev_t osdev, 
                                 uint8_t req,
                                 uint8_t reqtype,
                                 uint16_t value, 
                                 uint16_t index, 
                                 void *data, 
                                 uint32_t size)
{
	int32_t result = 0;
    uint32_t ret = 0;
    
#if 0
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "req = 0x%02x\n", req);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "reqtype = 0x%02x\n", reqtype);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "value = 0x%04x\n", value);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "index = 0x%04x\n", index);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "data = 0x%lx\n", (u32_t) data);
    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "size = %ld\n", size);
#endif

    if (reqtype == USB_DIR_IN) {
        result = usb_control_msg(osdev->udev, usb_rcvctrlpipe(osdev->udev, 0),
                                 req, reqtype | 0x40, value, index, data, size, HZ);
    } else {
        uint8_t* buf;
        
        if (size > 0) {
            buf = kmalloc(size, GFP_KERNEL);
            memcpy(buf, (uint8_t*)data, size);
        } else {
            buf = NULL;
        }
        
        result = usb_control_msg(osdev->udev, usb_sndctrlpipe(osdev->udev, 0),
                                 req, reqtype | 0x40, value, index, buf, size, HZ);
        kfree(buf);
    }

    if (result < 0)
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "athLnxUsbSubmitControl() failed, result=0x%x\n", result);
        ret = 1;
    }
    
    return ret;
}

#if ZM_USB_TX_STREAM_MODE
void
athLnx_rx_streammode_timeout_change(osdev_t osdev, u_int32_t val)
{
    //use global variable to pass the parameters
    osdev->upstream_reg                 = UPSTREAM_MODE_TIMEOUT_REGISTER;
    osdev->upstream_reg_write_value     = val;

    osdev->htcPutDeferItem(osdev,
        (void *)wmi_reg_write_single,
        WORK_ITEM_SET_RX_STREAMMODE_TIMEOUT,
        osdev,
        NULL,
        NULL);
}
#endif /*ZM_USB_TX_STREAM_MODE*/

u_int32_t
OS_Usb_SubmitMsgInUrb(osdev_t osdev)
{
    osdev->RegInFailCnt = 0;
    return athLnxSubmitRegInUrb(osdev);
}

u_int32_t 
OS_Usb_SubmitCmdOutUrb(osdev_t osdev, uint8_t* buf, uint16_t len, void *context)
{
    struct sk_buff * sendBuf = (struct sk_buff *)context;
    UsbUrbContext_t *ctx;
    UsbUrbContext_t *remain_ctx_pool[MAX_CMD_URB];
    int urb_num = 0;
    int offset = 0;
    int ii;
    int transfer_len;
    int ret;

    ctx = athLnxAllocCmdUrbCtx(osdev);

    if ( ctx == NULL ) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "!!Error can't get CmdOutUrb!!\n");
        return 1;
    }    
        
    ctx->buf = sendBuf;        

    transfer_len = sendBuf->len;
    transfer_len -= ZM_USB_REG_MAX_BUF_SIZE;

    /* We need to allocate another URB for more than 64 bytes transfer */
    while (transfer_len > 0) {
        UsbUrbContext_t *remain_ctx;
        int size;

        struct sk_buff * remain_buf = dev_alloc_skb(ZM_USB_REG_MAX_BUF_SIZE);

        if (remain_buf == NULL)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't allocate memory\n", __func__);

            ctx->inUse = 0;
            goto error;
        }

        remain_ctx = athLnxAllocCmdUrbCtx(osdev);

        if (remain_ctx == NULL)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: can't allocate UrbContext\n", __func__);

            ctx->inUse = 0;
            dev_kfree_skb_any(remain_buf);
            goto error;
        }

        offset += ZM_USB_REG_MAX_BUF_SIZE;
        size = (transfer_len > ZM_USB_REG_MAX_BUF_SIZE) ? ZM_USB_REG_MAX_BUF_SIZE : transfer_len;

        memcpy(remain_buf->data, &(buf[offset]), size);
        skb_put(remain_buf, size);

        remain_ctx->buf = remain_buf;
        remain_ctx->flags = 1;

        remain_ctx_pool[urb_num] = remain_ctx;
        urb_num++;

        transfer_len -= ZM_USB_REG_MAX_BUF_SIZE;
    }

    /*
     * CmdOut data size would large than 64 when multi-write.
     */
    ret = athLnxUsbSubmitBulkUrb(ctx->urb, osdev->udev, USB_REG_OUT_PIPE, USB_DIR_OUT, (void *)buf,
                               (sendBuf->len > ZM_USB_REG_MAX_BUF_SIZE) ? ZM_USB_REG_MAX_BUF_SIZE : sendBuf->len,
                               (usb_complete_t)athLnxUsbRegOut_callback, (void *)ctx);

    if (ret != 0) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s athLnxUsbSubmitBulkUrb fail, ret: 0x%08x\n", __func__, ret);
        ctx->inUse = 0;
        goto error;
    }

    for (ii = 0; ii < urb_num; ii++)
    {
        int status;
        struct sk_buff * cmd_buf = remain_ctx_pool[ii]->buf;

        /* TODO: handle error in each transaction */
        status = athLnxUsbSubmitBulkUrb(remain_ctx_pool[ii]->urb, osdev->udev, USB_REG_OUT_PIPE, USB_DIR_OUT,
                                       (void *)cmd_buf->data, cmd_buf->len,
                                       (usb_complete_t)athLnxUsbRegOut_callback, (void *)remain_ctx_pool[ii]);

        if (status != 0) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s athLnxUsbSubmitBulkUrb fail, status: 0x%08x\n", __func__, status);
            remain_ctx_pool[urb_num]->inUse = 0;
        }
    }

    return ret;

error:

    for (ii = 0; ii < urb_num; ii++)
    {
        /* free URB and buffers */
        remain_ctx_pool[urb_num]->inUse = 0;
        dev_kfree_skb_any(remain_ctx_pool[urb_num]->buf);
    }

    return 1;
}

u_int32_t
OS_Usb_SubmitRxUrb(osdev_t osdev)
{
    /* do nothing: Rx urb would submit in athLnxInitUsbRxQ() */
    return 0;
}

u_int32_t 
OS_Usb_SubmitTxUrb(osdev_t osdev, uint8_t* buf, uint16_t len, void *context, HIFUSBTxPipe *pipe)
{
    return athLnxUsbOut(osdev, (struct sk_buff *)context, pipe);
}

u_int16_t
OS_Usb_GetFreeTxBufferCnt(osdev_t osdev, HIFUSBTxPipe *pipe)
{
    u_int16_t freeTxBufCnt;
    unsigned long irqFlag;
    u_int16_t max_tx_buf_num = ((osdev->isMagpie == TRUE) ? ZM_MAX_TX_BUF_NUM : ZM_MAX_TX_BUF_NUM_K2);
        
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);   
    freeTxBufCnt = max_tx_buf_num - pipe->TxBufCnt;
    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
     
    return freeTxBufCnt;
}
u_int16_t
OS_Usb_GetMaxTxBufferCnt(osdev_t osdev)
{
    return ((osdev->isMagpie == TRUE) ? ZM_MAX_TX_BUF_NUM : ZM_MAX_TX_BUF_NUM_K2);
}

u_int16_t
OS_Usb_GetTxBufferCnt(osdev_t osdev, HIFUSBTxPipe *pipe)
{
    uint16_t TxBufCnt;
    unsigned long irqFlag;
    
    spin_lock_irqsave(&(osdev->cs_lock), irqFlag);
    TxBufCnt = pipe->TxBufCnt;
    spin_unlock_irqrestore(&(osdev->cs_lock), irqFlag);
    return TxBufCnt;
}

u_int16_t
OS_Usb_GetTxBufferThreshold(osdev_t osdev)
{
    return ZM_MAX_TX_AGGREGATE_NUM;    
}

u_int16_t
OS_Usb_GetFreeCmdOutBufferCnt(osdev_t osdev)
{
    return 1;
}

u_int16_t
OS_Usb_InitTxRxQ(osdev_t osdev)
{
    /* Initialize USB TxQ */
    athLnxInitUsbTxQ(osdev);

    /* Initialize USB RxQ */
    athLnxInitUsbRxQ(osdev);
    
    return 1;    
}

u_int32_t
athUsbFirmwareDownload(osdev_t osdev, uint8_t* fw, uint32_t len, uint32_t offset)
{
    u_int32_t uCodeOfst = offset;
    u_int32_t uTextOfst = ZM_FIRMWARE_TEXT_ADDR;
    u_int8_t *image, *ptr;
    u_int32_t result;
    u_int32_t ret = 0;
    u_int32_t fwdl_stat;    
    
    if (osdev->isMagpie == 0) uTextOfst = ZM_FIRMWARE_TEXT_ADDR;
    else                      uTextOfst = ZM_FIRMWARE_MAGPIE_TEXT_ADDR;	
	    
    image = (u_int8_t*) fw;
    ptr = image;
  
    while (len > 0) 
    {
        u_int32_t translen = (len > 4096) ? 4096 : len;

#if 0  /* 2009/12/18 all firmware would transfer to byte ordering. */
        u_int32_t ii;
        u_int32_t *pfw = (u_int32_t *)image;

        /* Convert firmware image to correct byte ordering */
        for (ii = 0; ii < (translen >> 2); ii++)
        {
            *pfw = cpu_to_le32(*pfw);
             pfw++;
        }
#endif

        result = athLnxUsbSubmitControl(osdev, FIRMWARE_DOWNLOAD, USB_DIR_OUT,
                                      (u_int32_t) (uCodeOfst >> 8), 
                                      0, image, translen);

        if (result != 0)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "FIRMWARE_DOWNLOAD failed\n");
            ret = 1;
            goto exit;
        }

        len -= translen;
        image += translen;
        uCodeOfst += translen; // in Word (16 bit)

        result = 0;
    }

    /* If download firmware success, issue a command to firmware */
    if (ret == 0)
    {   
        result = athLnxUsbSubmitControl(osdev, FIRMWARE_DOWNLOAD_COMP, USB_DIR_IN,
                                       (u_int32_t) (uTextOfst >> 8),
                                        0, &fwdl_stat, sizeof(fwdl_stat));
        
        fwdl_stat = le32_to_cpu(fwdl_stat);

        if (result != 0)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "FIRMWARE_DOWNLOAD_COMP failed\n");
            ret = 1;
            goto exit;
        }
        else if ((fwdl_stat&0xff) == 0x0)
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "SUCCESS [FW downlaod] -- confirmed by target. result = 0x%08x\n", 
                         result);
        }
        else
        {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "FAIL [FW download] -- 0x%08x said by target. result = 0x%08x\n", 
                          fwdl_stat, result);
            ret = 1;
            goto exit;            
        }
    }

exit:

    return ret;

}

int athLnxRebootCmd(osdev_t osdev)
{
    int ret;

    urb_t *RegOutUrb = USB_ALLOC_URB(0, GFP_KERNEL);
    u_int32_t cmd = 0xffffffff;

    ret = usb_bulk_msg(osdev->udev, usb_sndbulkpipe(osdev->udev, 4),
                &cmd, sizeof(cmd), NULL, HZ);

    usb_free_urb(RegOutUrb);
    return ret;
}

void athLnxFlushTxQ(osdev_t osdev)
{
    UsbTxQ_t *TxData, TxQ;

    /* Flush buffer in the TxQ */
    while ((TxData = athLnxGetUsbTxBuffer(osdev, &osdev->TxPipe, &TxQ)) != NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: free buffer in TxPipe\n", __func__);
        dev_kfree_skb_any(TxData->buf);
    }

    while ((TxData = athLnxGetUsbTxBuffer(osdev, &osdev->HPTxPipe, &TxQ)) != NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_INFO "%s: free buffer in HPTxPipe\n", __func__);
        dev_kfree_skb_any(TxData->buf);
    }
}

void athLnxFwRecover(osdev_t osdev)
{
    /* Watch dog Handler */
    if (osdev->enablFwRcv) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nstart FW recover \n");

        /* 1: Stop HTC/WMI */
        MpHtcSuspend(osdev);

        /* 2: Flush all Tx buffer */
        athLnxFlushTxQ(osdev);

        /* 3: Unlink and free all urbs */
        athLnxUnlinkAllUrbs(osdev);
        athLnxFreeAllUrbs(osdev);
#ifdef NBUF_PREALLOC_POOL
        athLnxFreeRegInBuf(osdev);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
        osdev->netdev->netdev_ops->ndo_stop(osdev->netdev);
#else
        osdev->netdev->stop(osdev->netdev);
#endif

        /* 3: Redownload firmware */
        msleep(100);

        if (athUsbFirmwareDownload(osdev, osdev->Image, osdev->ImageSize,
                ZM_FIRMWARE_WLAN_ADDR)) {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: athUsbFirmwareDownload fail!\n", __func__);

            osdev->enablFwRcv = 0;
            return;
        }
        else {
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s_%d: Firmware download success !\n", __func__, __LINE__);
            msleep(100);

            /* urb */
            if (!athLnxAllocAllUrbs(osdev)) {
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "%s: athLnxAllocAllUrbs fail!\n", __func__);
            }

            MpHtcResume(osdev);

            ath_usb_vap_restart(osdev->netdev);
            osdev->enablFwRcv = 0;

            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "\nFW recover finished\n");
        }
    }
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,20))
void athRecoverEvent(struct work_struct *work)
#else
void athRecoverEvent(void *data)
#endif
{
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,20))
    struct _NIC_DEV *osdev =
               container_of(work, struct _NIC_DEV, kevent);
#else
    struct _NIC_DEV *osdev = (struct _NIC_DEV *) data;
#endif

    if (osdev == NULL)
    {
        return;
    }

    down(&osdev->recover_sem);

    if (test_and_clear_bit(ATH_RECOVER_EVENT, &osdev->event_flags))
    {
        athLnxFwRecover(osdev);
    }

    up(&osdev->recover_sem);
}

void athLnxScheduleWorkQeueue(osdev_t osdev, int flag)
{
    if (osdev == NULL) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s osdev is NULL\n", __func__);
        return;
    }

    set_bit(flag, &osdev->event_flags);

    if (!schedule_work(&osdev->kevent))
    {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, KERN_ERR "schedule_task failed, flag = %x\n", flag);
    }
}

int athLnxCreateRecoverWorkQueue(osdev_t osdev)
{
    /* Create Mutex and keventd */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
    INIT_WORK(&osdev->kevent, athRecoverEvent, osdev);
#else
    INIT_WORK(&osdev->kevent, athRecoverEvent);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
    init_MUTEX(&osdev->recover_sem);
#else
    sema_init(&osdev->recover_sem, 1);
#endif

    return 0;
}

void
OS_Usb_Enable_FwRcv(osdev_t osdev)
{
    osdev->enablFwRcv = 1;
    athLnxScheduleWorkQeueue(osdev, ATH_RECOVER_EVENT);
}
