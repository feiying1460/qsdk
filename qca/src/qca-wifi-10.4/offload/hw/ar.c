/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <qdf_mem.h>
#include <qdf_nbuf.h>
#include <qdf_trace.h>
#include <bmi_msg.h>
#include <ar_internal.h>
/* QCA9888 currently shares QCA9984's handler */
extern struct ar_rx_desc_ops* ar9888_rx_attach(struct ar_s *ar);
extern struct ar_rx_desc_ops* ar900b_rx_attach(struct ar_s *ar);
extern struct ar_rx_desc_ops* qca9984_rx_attach(struct ar_s *ar);

struct ar_rx_desc_ops*
ar_rx_attach(ar_handle_t arh,
        rx_handle_t htt_pdev,
        qdf_device_t osdev,
        struct htt_rx_callbacks *cbs)
{
    struct ar_s *ar = (struct ar_s *)arh;
    struct ar_rx_desc_ops *ops = NULL;

    if(ar)
    {
        switch(ar->target_type)
        {
            case TARGET_TYPE_QCA9984:
            case TARGET_TYPE_QCA9888:
                ops = qca9984_rx_attach(ar);
                break;
            case TARGET_TYPE_AR900B:
            case TARGET_TYPE_IPQ4019:
                ops = ar900b_rx_attach(ar);
                break;
            case TARGET_TYPE_AR9888:
                ops = ar9888_rx_attach(ar);
                break;
            default:
                QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Invalid target %d\n", ar->target_type);
	}
        ar->htt_handle = htt_pdev;
        ar->osdev = osdev;
        ar->rx_callbacks = cbs;
    }
    return ops;
}

ar_handle_t ar_attach(int target_type)
{
    ar_handle_t arh;

    arh = qdf_mem_malloc(sizeof(struct ar_s));
    if (!arh) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "%s: unable to allocate memory\n", __func__);
        return NULL;
    }
    ((struct ar_s *)arh)->target_type = target_type;

    return arh;
}

void ar_detach(ar_handle_t arh)
{
    qdf_mem_free(arh);
}

