/*
 * Copyright (c) 2013,2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <asm/hardirq.h>
#include <linux/slab.h>
#include "mem_manager.h"

unsigned int mm_dbg_enable = 0x0;
module_param(mm_dbg_enable, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(mm_dbg_enable,"mm_dbg enable");
EXPORT_SYMBOL(mm_dbg_enable);

struct kmem_obj_s g_kmem_obj[RADIO_IDMAX][KM_MAXREQ];
struct cmem_obj_s g_cmem_obj[RADIO_IDMAX][CM_MAXREQ];

/* Alloates kmalloc memory once and will use the same for subsequent allocataions for the radio and type of allocation */
void* __wifi_kmem_allocation(int radio_id,int type,int size, int flags)
{
    MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s RadioId: %d type %d, size %d, flags %x\n", __func__, radio_id,type,size,flags);

    if ((type >= KM_MAXREQ) || (radio_id >= RADIO_IDMAX)) {
        return NULL;
    }

    if (g_kmem_obj[radio_id][type].addr != NULL) {
        MM_DEBUG_PRINT(MM_DEBUG_LVL2," %s already allocated size %d\n", __func__, g_kmem_obj[radio_id][type].size);
        if (g_kmem_obj[radio_id][type].size >= size) {
            return g_kmem_obj[radio_id][type].addr;
        } else {
            /* handle error condition */
            MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s size req %d size prev allocated %d", __func__, size,g_kmem_obj[radio_id][type].size);
            kfree(g_kmem_obj[radio_id][type].addr);
            g_kmem_obj[radio_id][type].size = 0;
        }
    }
    MM_DEBUG_PRINT(MM_DEBUG_LVL2," %s new allocation size %d\n", __func__, size);

    g_kmem_obj[radio_id][type].addr = kmalloc(size, flags);
    if (g_kmem_obj[radio_id][type].addr) {
        g_kmem_obj[radio_id][type].size = size;
    }

    return g_kmem_obj[radio_id][type].addr;
}

/* validates address that is getting freed but wont free the memory */
void __wifi_kmem_free(int radio_id, int type, int addr)
{
    if ((type >= KM_MAXREQ) || (radio_id >= RADIO_IDMAX)) {
        MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s unsupported type %d ", __func__, type);
        return;
    }

    MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s RadioId: %d type %d, addr %x\n", __func__, radio_id,type,addr);
    if (g_kmem_obj[radio_id][type].addr != (void *)addr) {
        MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s Error addr req %x addr prev allocated %p", __func__, addr,g_kmem_obj[radio_id][type].addr);
    }
}

/* Alloates dma memory once and will use the same for subsequent allocataions for the radio and type of allocation */
void* __wifi_cmem_allocation(int radio_id,int type,int size,void *pdev,unsigned int *paddr,int intr_ctxt)
{
    struct pci_dev *pcidev;
    int flags = GFP_KERNEL;

    MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s RadioId: %d type %d, size %d, pdev %p, intr_ctxt %d\n", __func__, radio_id,type,size,pdev,intr_ctxt);

    pcidev = (struct pci_dev *)pdev;

    if ((type >= CM_MAXREQ) || (radio_id >= RADIO_IDMAX)) {
        return NULL;
    }

    if(intr_ctxt) {
        flags = GFP_ATOMIC;
    }

    if (g_cmem_obj[radio_id][type].vaddr != NULL) {
        MM_DEBUG_PRINT(MM_DEBUG_LVL2," %s already allocated size %d\n", __func__,g_cmem_obj[radio_id][type].size);
        if (g_cmem_obj[radio_id][type].size >= size) {
            *paddr = g_cmem_obj[radio_id][type].paddr;
            return  g_cmem_obj[radio_id][type].vaddr;
        } else {
            /* handle error condition */
            MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s size req %d size prev allocated %d\n", __func__, size,g_cmem_obj[radio_id][type].size);
	    dma_free_coherent(pcidev == NULL ? NULL : &(pcidev->dev),g_cmem_obj[radio_id][type].size , g_cmem_obj[radio_id][type].vaddr,g_cmem_obj[radio_id][type].paddr);
	    g_cmem_obj[radio_id][type].size = 0;
        }
    }

    MM_DEBUG_PRINT(MM_DEBUG_LVL2," %s new allocation size %d\n", __func__, size);

    g_cmem_obj[radio_id][type].vaddr = dma_alloc_coherent(pcidev == NULL ? NULL : &(pcidev->dev), size, &g_cmem_obj[radio_id][type].paddr, flags);
    if (g_cmem_obj[radio_id][type].vaddr) {
        g_cmem_obj[radio_id][type].size = size;
        *paddr = g_cmem_obj[radio_id][type].paddr;
    }

    return g_cmem_obj[radio_id][type].vaddr;
}

/* validates address that is getting freed but wont free the memory */
void __wifi_cmem_free(int radio_id, int type, int addr)
{
    MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s RadioId: %d type %d, addr %x\n", __func__, radio_id,type,addr);

    if ((type >= CM_MAXREQ) || (radio_id >= RADIO_IDMAX)) {
        MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s unsupported type %d ", __func__, type);
        return;
    }

    if (g_cmem_obj[radio_id][type].vaddr != (void *)addr) {
        MM_DEBUG_PRINT(MM_DEBUG_LVL1," %s Error addr req %x addr prev allocated %p", __func__, addr,g_cmem_obj[radio_id][type].vaddr);
    }
}

static int __mm_init_module(void)
{
    int i,j;

    for (i = 0; i < RADIO_IDMAX; i++) {
        for (j = 0; j < KM_MAXREQ; j++) {
            g_kmem_obj[i][j].addr = NULL;
            g_kmem_obj[i][j].size = 0;
        }
    }

    for (i = 0; i < RADIO_IDMAX; i++) {
        for (j = 0; j < CM_MAXREQ; j++) {
            g_cmem_obj[i][j].paddr = 0;
            g_cmem_obj[i][j].vaddr = NULL;
            g_cmem_obj[i][j].size = 0;
        }
    }

    MM_DEBUG_PRINT(MM_DEBUG_LVL2, "%s \n", __func__);
    return 0;
}

static void __mm_exit_module(void)
{
    int i,j;

    for (i = 0; i < RADIO_IDMAX; i++) {
        for (j = 0; j < KM_MAXREQ; j++) {
            if(g_kmem_obj[i][j].addr != NULL) {
                kfree(g_kmem_obj[i][j].addr);
            }
        }
    }

    for (i = 0; i < RADIO_IDMAX; i++) {
        for (j = 0; j < CM_MAXREQ; j++) {
            if(g_cmem_obj[i][j].vaddr != NULL) {
                pci_free_consistent(NULL, g_cmem_obj[i][j].size, g_cmem_obj[i][j].vaddr, g_cmem_obj[i][j].paddr);
            }
        }
    }

    MM_DEBUG_PRINT(MM_DEBUG_LVL2, "%s \n", __func__);
}

EXPORT_SYMBOL(__wifi_kmem_allocation);
EXPORT_SYMBOL(__wifi_kmem_free);
EXPORT_SYMBOL(__wifi_cmem_allocation);
EXPORT_SYMBOL(__wifi_cmem_free);

module_init(__mm_init_module);
module_exit(__mm_exit_module);
