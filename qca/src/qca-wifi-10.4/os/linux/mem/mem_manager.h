/*
 * Copyright (c) 2013,2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


#define MM_DEBUG_LVL1 0x1
#define MM_DEBUG_LVL2 0x2

#define MM_DEBUG_MASK(mask)  (mm_dbg_enable & mask)

#define MM_DEBUG_PRINT(mask, args...) do { \
    if (MM_DEBUG_MASK(mask)) {  \
        printk(args);    \
    }                    \
} while (0)

enum {
    RADIO_ID0 = 0,
    RADIO_ID1 = 1,
    RADIO_ID2 = 2,
    RADIO_IDMAX,
};

/* unique id for consistent memory allocation */
enum {
    CM_FWREQ = 0,
    CM_FWREQMAX = 31,
    CM_CODESWAP,
    CM_CODESWAP_MAX = 39,
    CM_RX_ATTACH_PADDR_RING,
    CM_RX_ATTACH_ALLOC_IDX_VADDR,
    CM_TX_ATTACH_POOL_VADDR,
    CM_TX_ATTACH_FRAG_POOL_VADDR,
    CM_MAXREQ = 44,
};

/* unique id for kmalloc memory allocation */
enum {
    KM_WIFIPOS = 0,
    KM_MAXREQ = 32,
};

struct kmem_obj_s {
    void *addr;
    size_t size;
};

struct cmem_obj_s {
    void *vaddr;
    unsigned int paddr;
    size_t size;
};


void* __wifi_kmem_allocation(int radio_id,int type,int size, int flags);
void __wifi_kmem_free(int radio_id, int type, int addr);
void* __wifi_cmem_allocation(int radio_id,int type,int size,void *pdev,unsigned int *paddr,int intr_ctxt);
void __wifi_cmem_free(int radio_id, int type, int addr);

#define wifi_kmem_allocation __wifi_kmem_allocation
#define wifi_kmem_free __wifi_kmem_free
#define wifi_cmem_allocation __wifi_cmem_allocation
#define wifi_cmem_free __wifi_cmem_free
