/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */


#include <asf_amem.h>

#include <asf_print.h> /* asf_print */

/*--- configuration defaults ---*/

#ifndef ASF_AMEM_LIMIT_BYTES
    #define ASF_AMEM_LIMIT_BYTES 0  /* initial limit on total memory size */
#endif

#ifndef ASF_AMEM_CACHE_ALIGN_POW2
    #define ASF_AMEM_CACHE_ALIGN_POW2 3  /* align to 8-byte boundaries */
#endif

/*--- definitions ---*/

enum {
    ASF_AMEM_CAT_ALLOC,
    ASF_AMEM_CAT_FREE,
    ASF_AMEM_CAT_STATUS,
    ASF_AMEM_CAT_LEAK,
};

enum {
    ASF_AMEM_VERB_ERR,
    ASF_AMEM_VERB_WARN,
    ASF_AMEM_VERB_INFO,
};

/*
 * If no chunk size is explicitly specified,
 * expand memory pools 4 elems at a time.
 */
#define ASF_AMEM_DEFAULT_CHUNK 4

typedef unsigned long long asf_amem_cntr_t;

/* asf_amem_leak_debug -- holds debug info that helps identify memory leaks */
struct asf_amem_leak_debug {
    struct asf_amem_leak_debug *prev;
    struct asf_amem_leak_debug *next;
    const char *file;
    int line;
    asf_amem_size_t bytes;
    asf_amem_cntr_t counter;
};

/* round up to a power of two */
#define ASF_AMEM_CEIL_POW2(value, power_of_2) \
    ((((value) + ((1 << (power_of_2))-1)) >> (power_of_2)) << (power_of_2))

#define ASF_AMEM_MARKER_CHECK_MAGIC1 0xD1ffDaff
#define ASF_AMEM_MARKER_CHECK_MAGIC2 0xA11Bad
#define ASF_AMEM_OOB_HEADER_BYTES  16
#define ASF_AMEM_OOB_FOOTER_BYTES 16
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
struct asf_amem_debug_header {
    struct asf_amem_leak_debug leak;
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    unsigned marker;
#endif
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
    /* padding for out-of-bounds check - keep this last */
    unsigned char oob[ASF_AMEM_OOB_HEADER_BYTES];
#endif
};
#endif

struct asf_amem_debug_footer {
    /* padding for out-of-bounds check - keep this first */
    unsigned char oob[ASF_AMEM_OOB_FOOTER_BYTES];
};

/* header added to amalloc allocations, and associated macros */
struct asf_amem_alloc_header {
    asf_amem_size_t user_bytes;
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    struct asf_amem_debug_header dbg;
#endif
};

/* align user allocation to an alignment boundary */
#define ASF_AMEM_ALLOC_HEADER_SIZE \
    ASF_AMEM_CEIL_POW2(            \
        sizeof(struct asf_amem_alloc_header), ASF_AMEM_CACHE_ALIGN_POW2)
#define ASF_AMEM_MOVE_PAST_ALLOC_HEADER(x) \
    (((char *)x) + ASF_AMEM_ALLOC_HEADER_SIZE)
#define ASF_AMEM_REWIND_TO_ALLOC_HEADER(x) \
    (((char *)x) - ASF_AMEM_ALLOC_HEADER_SIZE)

/* align allocation footer to an alignment boundary */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
    #define ASF_AMEM_ALLOC_FOOTER_SIZE \
        ASF_AMEM_CEIL_POW2(             \
            sizeof(struct asf_amem_debug_footer), ASF_AMEM_CACHE_ALIGN_POW2)
    #define ASF_AMEM_ALLOC_FOOTER_PAD \
        (ASF_AMEM_ALLOC_FOOTER_SIZE - sizeof(struct asf_amem_debug_footer))
    #define ASF_AMEM_MOVE_TO_FOOTER(head_ptr) \
        ( /* to reach the data portion of the footer... */ \
        /* start at the front */                           \
        ((char *) head_ptr)                                \
        /* go past the header */                           \
        + ASF_AMEM_ALLOC_HEADER_SIZE                       \
        /* go past the user data */                        \
        + head_ptr->user_bytes                             \
        /* go past the footer alignment-pad */             \
        + ASF_AMEM_ALLOC_FOOTER_PAD)
#else
    #define ASF_AMEM_ALLOC_FOOTER_SIZE 0
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG */

#define ASF_AMEM_ALLOC_PAD \
    (ASF_AMEM_ALLOC_HEADER_SIZE + ASF_AMEM_ALLOC_FOOTER_SIZE)

/* header added to asf_amem_cache_alloc allocations, and associated macros */
struct asf_amem_elem_free_node {
    struct asf_amem_elem_free_node *next;
};

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
struct asf_amem_elem_header {
    struct asf_amem_debug_header dbg;
};
    #define ASF_AMEM_ELEM_HEADER_SIZE \
        ASF_AMEM_CEIL_POW2(           \
            sizeof(struct asf_amem_elem_header), ASF_AMEM_CACHE_ALIGN_POW2)
#else
    #define ASF_AMEM_ELEM_HEADER_SIZE 0
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    #define ASF_AMEM_ELEM_FOOTER_SIZE \
        ASF_AMEM_CEIL_POW2(           \
            sizeof(struct asf_amem_debug_footer), ASF_AMEM_CACHE_ALIGN_POW2)
#else
    #define ASF_AMEM_ELEM_FOOTER_SIZE 0
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */

/* align user buffer within the element to an alignment boundary */
#define ASF_AMEM_MOVE_PAST_ELEM_HEADER(x) \
    (((char *)x) + ASF_AMEM_ELEM_HEADER_SIZE)
#define ASF_AMEM_REWIND_TO_ELEM_HEADER(x) \
    (((char *)x) - ASF_AMEM_ELEM_HEADER_SIZE)

/* align element footer to an alignment boundary */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
    #define ASF_AMEM_ELEM_FOOTER_PAD \
        (ASF_AMEM_ELEM_FOOTER_SIZE - sizeof(struct asf_amem_debug_footer))
    #define ASF_AMEM_MOVE_TO_ELEM_FOOTER(elem_ptr, elem_bytes) \
        ( /* to reach the data portion of the footer... */     \
        /* start at the front */                               \
        ((char *) elem_ptr)                                    \
        /* go past the header */                               \
        + ASF_AMEM_ELEM_HEADER_SIZE                            \
        /* go past the user data */                            \
        + elem_bytes                                           \
        /* go past the footer alignment-pad */                 \
        + ASF_AMEM_ELEM_FOOTER_PAD)
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG */

#define ASF_AMEM_ELEM_PAD \
    (ASF_AMEM_ELEM_HEADER_SIZE + ASF_AMEM_ELEM_FOOTER_SIZE)

/* header added to asf_amem_cache_add chunks, and associated macros */
struct asf_amem_chunk_header {
    struct asf_amem_chunk_header *next;
};
/* The data that comes after the chunk header could be either
 * asf_amem_elem_header or user data, if the asf_amem_elem_header has been
 * conditionally-compiled out.
 * So, to be safe, align to an alignment boundary.
 */
#define ASF_AMEM_CHUNK_PAD() \
    ASF_AMEM_CEIL_POW2(      \
        sizeof(struct asf_amem_chunk_header), ASF_AMEM_CACHE_ALIGN_POW2)
#define ASF_AMEM_MOVE_PAST_CHUNK_HEADER(x) \
    (((char *)x) + ASF_AMEM_CHUNK_PAD())

struct asf_amem_cache {
    /*
     * Meta-information about this memory pool,
     * used for monitoring and debugging.
     */
    struct {
        struct asf_amem_cache *next; /* keep all caches in a list */
        const char *name;
        const char *file;
        int line;
        #if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
        asf_amem_size_t req_bytes;
        struct asf_amem_leak_debug *alloc_list;
        #endif
    } meta;

    /*
     * Remember which asf_amem instance this memory pool is associated with.
     * This indirectly indicates what type of memory this memory pool
     * consists of - the asf_amem instance has functions to allocate and
     * free memory of a given type.
     */
    asf_amem_instance_handle asf_amem_inst;

    /*
     * Keep track of the chunks of memory we've allocated
     * to be carved up into elements.
     */
    struct asf_amem_chunk_header *chunklist;
    /*
     * Keep track of unallocated elements.
     */
    struct asf_amem_elem_free_node *freelist;
    asf_amem_size_t elem_bytes;
    int num_elem;
    int max_elem;
    int chunk_elem;
    /*
     * We could traverse the freelist to find the number of free elems,
     * but it saves time and effort to keep a running count of free elems.
     */
    int free_elem;
};

/* specifications regarding which allocations appear to be leaks */
#define ASF_AMEM_LEAK_MIN_AGE_RANGE 1000
#define ASF_AMEM_LEAK_LIM_OLD_PCT 25
#define ASF_AMEM_LEAK_LIM_NEW_PCT 50

struct asf_amem_instance {
    asf_amem_cntr_t event_counter;
    asf_amem_size_t total_bytes;
    asf_amem_size_t limit_bytes;
    struct asf_amem_cache *cache_list;
    asf_amem_alloc_fp alloc_func;
    asf_amem_free_fp free_func;
    void *osdev;
    asf_amem_lock_fp lock_func;
    asf_amem_unlock_fp unlock_func;
    void *lock;
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    /* allocated pool elems */
    struct asf_amem_leak_debug *alloc_list;
    struct {
        int min_age_range;
        int lim_old_pct;
        int lim_new_pct;
    } leak;
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */
    const char *name;
    asf_amem_instance_handle next;
};

/*--- declarations ---*/

static enum asf_amem_status asf_amem_cache_add(
    asf_amem_cache_handle handle,
    int add_elem);
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
static void asf_amem_cache_status_print(struct asf_amem_cache *p);
#endif
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
static void asf_amem_alloc_print(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *alloc,
    enum asf_amem_alloc_type which,
    unsigned whichMask,
    asf_amem_cntr_t oldest);
static void asf_amem_cache_allocs_print(
    asf_amem_cache_handle handle,
    enum asf_amem_alloc_type which,
    asf_amem_cntr_t oldest,
    int condense);
static void asf_amem_alloc_list_print(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *ptr,
    enum asf_amem_alloc_type which,
    unsigned whichMask,
    asf_amem_cntr_t oldest,
    int condense);
static asf_amem_cntr_t asf_amem_oldest_counter(asf_amem_instance_handle inst);
static void asf_amem_leak_debug_init(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *ptr,
    const char *file,
    int line,
    asf_amem_size_t bytes,
    struct asf_amem_leak_debug **list);
static void asf_amem_leak_debug_remove(
    struct asf_amem_leak_debug *ptr,
    struct asf_amem_leak_debug **list);
#endif

/*--- global variables ---*/

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
/* asf_amem_print_ctrl
 * Private print control struct used to control amem printouts.
 */
struct asf_print_ctrl asf_amem_print_ctrl;
#endif

/* asf_amem_std:
 * Standard instance of asf_amem memory management.
 * This is the asf_amem instance that all functions operate on, other than
 * the "_adv" advanced functions, which allow a specific asf_amem instance
 * to be specified.
 */
//struct asf_amem_instance asf_amem_std = {
#define asf_amem_std asf_amem
struct asf_amem_instance asf_amem = {
    0,                /* event_counter */
    0,                /* total_bytes */
    ASF_AMEM_LIMIT_BYTES, /* limit_bytes */
    NULL,             /* cache_list */
    NULL,             /* alloc_func */
    NULL,             /* free_func */
    NULL,             /* osdev */
    NULL,             /* lock_func */
    NULL,             /* unlock_func */
    NULL,             /* lock */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    NULL,             /* alloc_list */
    {
        ASF_AMEM_LEAK_MIN_AGE_RANGE, /* min_age_range */
        ASF_AMEM_LEAK_LIM_OLD_PCT,   /* lim_old_pct */
        ASF_AMEM_LEAK_LIM_NEW_PCT,   /* lim_new_pct */
    },
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */
    "standard",       /* name */
    NULL,             /* next */
};

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
const char *asf_amem_status_strings[asf_amem_status_num_values] = {
    "success",
    "bad handle",
    "bad params",
    "unfreed elem",
    "malloc fail",
};
#endif

/*--- API functions ---*/

void asf_amem_setup(
    asf_amem_alloc_fp alloc_func,
    asf_amem_free_fp free_func,
    void *osdev,
    asf_amem_lock_fp lock_func,
    asf_amem_unlock_fp unlock_func,
    void *lock)
{
    asf_amem.alloc_func = alloc_func;
    asf_amem.free_func = free_func;
    asf_amem.osdev = osdev;
    asf_amem.lock_func = lock_func;
    asf_amem.unlock_func = unlock_func;
    asf_amem.lock = lock;

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
    {
        int i;
        /* turn on all amem printout categories */
        for (i = 0; i < ASF_PRINT_MASK_BYTES; i++) {   
            asf_amem_print_ctrl.category_mask[i] = ~0;
        }
        /* set the amem printout verbosity to be high */
        asf_amem_print_ctrl.verb_threshold = ASF_AMEM_VERB_INFO;
        asf_amem_print_ctrl.name = "amem";
        asf_amem_print_ctrl.num_bit_specs = 0;
        /*
         * Register amem's print control struct with asf_print, so
         * asf_print's user interface can be used to modify amem's
         * print control struct.
         */
        asf_print_ctrl_register(&asf_amem_print_ctrl);
    }
#endif    
}

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
const char *asf_amem_status_to_string(enum asf_amem_status status)
{
    if ( status < 0 || status >= asf_amem_status_num_values ) {
        return "(invalid)";
    }
    return asf_amem_status_strings[status];
}
#endif

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
/* asf_amem_marker_has_error
 * Check the allocation header to make sure the magic pattern
 * stamped on the header during allocation is still intact.
 * Returns:
 *   0  if the marker is intact
 *   1  if the marker shows the buffer has been freed multiple times
 *   2  if the marker shows the buffer has been clobbered,
 *      or possibly freed multiple times
 */
static int asf_amem_marker_has_error(
    unsigned *marker, const char *file, int line)
{
    if (*marker != ASF_AMEM_MARKER_CHECK_MAGIC1) {
        /*
         * Error - the header may have been clobbered,
         * or the buffer may have been freed twice.
         * We can't say for sure which it is - once we return the
         * memory to the system's heap, the marker may be overwritten
         * by data from the next user of the buffer.
         * In this case, we'd be unable to distinguish a duplicate call
         * to afree from a case where the buffer's header is clobbered
         * prior to an initial call to afree.
         */
        if (*marker == ASF_AMEM_MARKER_CHECK_MAGIC2) {
            /* this has to be a duplicate call to afree */
            asf_print(&asf_amem_print_ctrl,
                ASF_AMEM_CAT_FREE, ASF_AMEM_VERB_ERR,
                "*** ERROR: duplicate call to afree "
                "for from %s, line %d\n", file, line);
            /*
             * Since the memory was already freed before,
             * returning is definitely the right thing to do.
             */
            return 1; /* definitely duplicate free */
        } else {
            asf_print(&asf_amem_print_ctrl,
                ASF_AMEM_CAT_FREE, ASF_AMEM_VERB_ERR,
                "*** ERROR: afree call from %s, line %d: "
                "buffer has been clobbered,\n"
                "or possibly freed multiple times\n",
                file, line);
            return 2; /* probably clobbered */
        }
    }
    *marker = ASF_AMEM_MARKER_CHECK_MAGIC2;
    return 0; /* no duplicate free or clobber */
}
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */

asf_amem_cache_handle asf_amem_cache_create_private(
    const char *file,
    int line,
    const char *name,
    asf_amem_size_t elem_bytes,
    int min_elems,
    int max_elems,
    int chunk_elems,
    asf_amem_instance_handle inst )
{
    asf_amem_cache_handle handle;

    if ( ! inst ) {
        inst = &asf_amem_std;
    }

    /* allocate memory for the pool descriptor (from standard memory) */
    handle = amalloc_adv(&asf_amem_std, sizeof(struct asf_amem_cache), NULL);
    if ( ! handle ) {
        return NULL;
    }

    /*
     * Remember what asf_amem instance this pool is associated with
     * (and thus what type of memory this pool uses).
     */
    handle->asf_amem_inst = inst;

    /* initialize the pool descriptor */
    handle->meta.file = file;
    handle->meta.line = line;
    handle->meta.name = name;
    #if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    handle->meta.alloc_list = NULL;
    handle->meta.req_bytes = elem_bytes;
    #endif

    handle->free_elem = 0;
    handle->num_elem = 0;
    handle->max_elem = max_elems;
    handle->chunk_elem =
        (chunk_elems > 0) ? chunk_elems : ASF_AMEM_DEFAULT_CHUNK;
    handle->freelist = NULL;
    handle->chunklist = NULL;

    /*
     * Each element has to be large enough to hold either the
     * user's requested buffer or the freelist's "next" pointer.
     */
    if ( elem_bytes < sizeof(struct asf_amem_elem_free_node) ) {
        elem_bytes = sizeof(struct asf_amem_elem_free_node);
    }

    /*
     * Simple method for giving sequential elements in the chunk
     * the proper alignment:  round up elem_bytes to the conservative
     * alignment boundary ASF_AMEM_CACHE_ALIGN_POW2.
     * It would be more efficient to align small allocations
     * (elem_bytes < 2^ASF_AMEM_CACHE_ALIGN_POW2) by rounding down
     * elem_bytes to a power of 2, e.g. aligning a 4-byte element
     * to a 4-byte boundary.  However, it's questionable whether the
     * improved efficiency merits the added complexity.
     */
    elem_bytes = ASF_AMEM_CEIL_POW2(elem_bytes, ASF_AMEM_CACHE_ALIGN_POW2);

    handle->elem_bytes = elem_bytes;

    /* make the initial minimum allocation */
    if (asf_amem_cache_add(handle, min_elems) != asf_amem_status_success) {
        afree_adv(&asf_amem_std, handle);
        return NULL;
    }

    handle->meta.next = inst->cache_list;
    inst->cache_list = handle;

    return handle;
}

void *asf_amem_cache_alloc_private(
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    const char *file, int line,
#endif
    asf_amem_cache_handle handle)
{
    void *user_ptr;
    if ( ! handle ) {
        return NULL; /* sanity check */
    }

    handle->asf_amem_inst->event_counter++;
    /* see if the memory pool is exhausted */
    if ( ! handle->freelist ) {
        int add_elems;
        /* see if we're allowed to expand */
        if (handle->max_elem > 0 &&
            handle->num_elem == handle->max_elem)
        {
            return NULL;
        }
        /* add more elements */
        add_elems = (handle->max_elem > 0) ?
            handle->max_elem - handle->num_elem : handle->chunk_elem;
        if (add_elems > handle->chunk_elem) {
            add_elems = handle->chunk_elem;
        }
        if (asf_amem_cache_add(handle, add_elems) != asf_amem_status_success) {
            return NULL;
        }
    }

    /*
     * Either there already was at least one element on the freelist,
     * or the freelist was successfully expanded.
     */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    {
        struct asf_amem_elem_header *hdr;
        hdr = (struct asf_amem_elem_header *)
            ASF_AMEM_REWIND_TO_ELEM_HEADER(handle->freelist);
        asf_amem_leak_debug_init(
            handle->asf_amem_inst, &hdr->dbg.leak, file, line,
            handle->meta.req_bytes, &handle->meta.alloc_list);
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
        hdr->dbg.marker = ASF_AMEM_MARKER_CHECK_MAGIC1;
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
        {
            struct asf_amem_debug_footer *foot_ptr;
            int i;

            for (i = 0; i < ASF_AMEM_OOB_HEADER_BYTES ; i++) {
                hdr->dbg.oob[i] = 0xbc;
            }
            foot_ptr = (struct asf_amem_debug_footer *)
                ASF_AMEM_MOVE_TO_ELEM_FOOTER(hdr, handle->meta.req_bytes);
            for (i = 0; i < ASF_AMEM_OOB_FOOTER_BYTES ; i++) {
                foot_ptr->oob[i] = 0xbc;
            }
        }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG */
    }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */

    user_ptr = (void *) handle->freelist;
    handle->freelist = handle->freelist->next; /* remove from freelist */
    handle->free_elem--;
    return user_ptr;
}

enum asf_amem_status
asf_amem_cache_free_private(
    asf_amem_cache_handle handle,
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    const char *file, int line,
#endif
    void *user_ptr)
{
    struct asf_amem_elem_free_node *elem_ptr;

    if ( ! handle ) {
        return asf_amem_status_bad_handle;
    }

    handle->asf_amem_inst->event_counter++;
    elem_ptr = (struct asf_amem_elem_free_node *) user_ptr;

    /* push back onto the freelist */
    elem_ptr->next = handle->freelist;
    handle->freelist = elem_ptr;
    handle->free_elem++;

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    /* remove from alloc list */
    {
        struct asf_amem_elem_header *hdr;
        hdr = (struct asf_amem_elem_header *)
            ASF_AMEM_REWIND_TO_ELEM_HEADER(handle->freelist);
        asf_amem_leak_debug_remove(&hdr->dbg.leak, &handle->meta.alloc_list);
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
        {
            enum asf_amem_status status;
            int error = asf_amem_marker_has_error(&hdr->dbg.marker, file, line);
            if (error) {
                /*
                 * Don't free the buffer.
                 * Either the buffer has already been freed, in which
                 * case we definitely shouldn't free it again,
                 * or the buffer's header has been clobbered.
                 * If the buffer's header is clobbered, it will probably
                 * be a bigger problem to free the buffer than to leak
                 * memory by not freeing it.
                 */
               status = (error == 1) ?
                   asf_amem_status_duplicate_free :
                   asf_amem_status_corruption;
               return status;
            }
        }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
        {
            struct asf_amem_debug_footer *foot_ptr;
            int i, num_corrupted_bytes = 0;

            for (i = 0; i < ASF_AMEM_OOB_HEADER_BYTES ; i++) {
                if (hdr->dbg.oob[i] != 0xbc) {
                    num_corrupted_bytes++;
                }
            }
            foot_ptr = (struct asf_amem_debug_footer *)
                ASF_AMEM_MOVE_TO_ELEM_FOOTER(hdr, handle->meta.req_bytes);
            for (i = 0; i < ASF_AMEM_OOB_FOOTER_BYTES ; i++) {
                if (foot_ptr->oob[i] != 0xbc) {
                    num_corrupted_bytes++;
                }
            }
            if (num_corrupted_bytes > 0) {
                asf_print(&asf_amem_print_ctrl,
                    ASF_AMEM_CAT_FREE, ASF_AMEM_VERB_ERR,
                    "*** ERROR: %d bytes corrupted before/behind buffer 0x%p, "
                    "freed from %s, line %d\n",
                    num_corrupted_bytes, user_ptr, file, line);
            }
        }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */
    }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */
    return asf_amem_status_success;
}

enum asf_amem_status asf_amem_cache_destroy(asf_amem_cache_handle handle)
{
    struct asf_amem_chunk_header *chunk_ptr;

    if ( ! handle ) {
        return asf_amem_status_bad_handle;
    }

    /* make sure all elements have been freed */
    if ( handle->num_elem != handle->free_elem ) {
        return asf_amem_status_unfreed_elem;
    }

    /* remove this from the cachelist */
    if ( handle->asf_amem_inst->cache_list == handle ) {
        handle->asf_amem_inst->cache_list =
            handle->asf_amem_inst->cache_list->meta.next;
    } else {
        struct asf_amem_cache *prev = handle->asf_amem_inst->cache_list;
        while ( prev ) {
            if ( prev->meta.next == handle ) {
                prev->meta.next = handle->meta.next;
                break;       
            }
        }
    }

    /* free all chunks */
    chunk_ptr = handle->chunklist;
    while ( chunk_ptr ) {
        struct asf_amem_chunk_header *next;
        next = chunk_ptr->next;
        /* the chunks get freed based on their memory type (asf_amem_inst) */
        afree_adv(handle->asf_amem_inst, chunk_ptr);
        chunk_ptr = next;
    }

    /* free the header (which was allocated from the standard memory type) */
    afree_adv(&asf_amem_std, handle);

    return asf_amem_status_success;
}

void * __ahdecl amalloc_private(
    asf_amem_instance_handle inst,
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    const char *file, int line,
#endif
    asf_amem_size_t user_bytes,
    asf_amem_constructor_fp constructor)
{
    void *p = NULL;
#if ASF_AMEM_SUPPORT == ASF_AMEM_SUPPORT_PASS_THRU
    if (! inst) {
        inst = &asf_amem_std;
    }
    p = (inst->alloc_func) ? inst->alloc_func(inst->osdev, user_bytes) : NULL;
#else
    asf_amem_size_t bytes;
    struct asf_amem_alloc_header *ptr;

    if (! inst) {
        inst = &asf_amem_std;
    }
    if ( ! inst->alloc_func ) {
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS
        asf_print(&asf_amem_print_ctrl, ASF_AMEM_CAT_ALLOC, ASF_AMEM_VERB_ERR,
            "*** ERROR: No memory-allocation function has been registered");
#endif
        return NULL;
    }

    if (inst->lock_func) {
        inst->lock_func(inst->lock);
    }
    inst->event_counter++;
    bytes = user_bytes + ASF_AMEM_ALLOC_PAD;
    if ( inst->limit_bytes > 0 &&
         inst->total_bytes + bytes > inst->limit_bytes ) {
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS
        asf_print(&asf_amem_print_ctrl, ASF_AMEM_CAT_ALLOC, ASF_AMEM_VERB_WARN,
            "New allocation would exceed mem limit: "
            "current = %lld, new = %lld, limit = %lld\n",
            (long long) inst->total_bytes,
            (long long) bytes,
            (long long) inst->limit_bytes);
#endif
        goto done;
    }
    ptr = inst->alloc_func(inst->osdev, bytes);
    if ( ! ptr ) {
        goto done;
    }
    inst->total_bytes += bytes;
    ptr->user_bytes = user_bytes;

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    asf_amem_leak_debug_init(
        inst, &ptr->dbg.leak, file, line, user_bytes, &inst->alloc_list);
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    ptr->dbg.marker = ASF_AMEM_MARKER_CHECK_MAGIC1;
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
    {
        struct asf_amem_debug_footer *foot_ptr;
        int i;

        for (i = 0; i < ASF_AMEM_OOB_HEADER_BYTES ; i++) {
            ptr->dbg.oob[i] = 0xbc;
        }
        foot_ptr = (struct asf_amem_debug_footer *)
            ASF_AMEM_MOVE_TO_FOOTER(ptr);
        for (i = 0; i < ASF_AMEM_OOB_FOOTER_BYTES ; i++) {
            foot_ptr->oob[i] = 0xbc;
        }
    }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG */

    p = ASF_AMEM_MOVE_PAST_ALLOC_HEADER(ptr);

done:
    if (inst->unlock_func) {
        inst->unlock_func(inst->lock);
    }
#endif
    if (p && constructor) {
        constructor(p, user_bytes);
    }
    return p;
}

void __ahdecl afree_private(
    asf_amem_instance_handle inst,
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    const char *file, int line,
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */
    void *user_ptr)
{
#if ASF_AMEM_SUPPORT == ASF_AMEM_SUPPORT_PASS_THRU
    if ( ! inst ) {
        inst = &asf_amem_std;
    }
    if (inst->free_func) {
        inst->free_func(user_ptr);
    }
#else
    struct asf_amem_alloc_header *ptr; 

    if ( ! inst ) {
        inst = &asf_amem_std;
    }
    if ( ! inst->free_func ) {
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS
        asf_print(&asf_amem_print_ctrl, ASF_AMEM_CAT_FREE, ASF_AMEM_VERB_ERR,
            "*** ERROR: No memory-deallocation function has been registered");
#endif
        return;
    }

    if (inst->lock_func) {
        inst->lock_func(inst->lock);
    }
    inst->event_counter++;
    ptr = (struct asf_amem_alloc_header *)
        ASF_AMEM_REWIND_TO_ALLOC_HEADER(user_ptr);
    inst->total_bytes -= ptr->user_bytes + ASF_AMEM_ALLOC_PAD;

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    /* remove this allocation from the list of allocations */
    asf_amem_leak_debug_remove(&ptr->dbg.leak, &inst->alloc_list);
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    if (asf_amem_marker_has_error(&ptr->dbg.marker, file, line)) {
        /*
         * Don't free the buffer.
         * Either the buffer has already been freed, in which
         * case we definitely shouldn't free it again,
         * or the buffer's header has been clobbered.
         * If the buffer's header is clobbered, it will probably
         * be a bigger problem to free the buffer than to leak
         * memory by not freeing it.
         */
        if (inst->unlock_func) {
            inst->unlock_func(inst->lock);
        }
        return;
    }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG
    {
        struct asf_amem_debug_footer *foot_ptr;
        int i, num_corrupted_bytes = 0;

        for (i = 0; i < ASF_AMEM_OOB_HEADER_BYTES ; i++) {
            if (ptr->dbg.oob[i] != 0xbc) {
                num_corrupted_bytes++;
            }
        }
        foot_ptr = (struct asf_amem_debug_footer *)
            ASF_AMEM_MOVE_TO_FOOTER(ptr);
        for (i = 0; i < ASF_AMEM_OOB_FOOTER_BYTES ; i++) {
            if (foot_ptr->oob[i] != 0xbc) {
                num_corrupted_bytes++;
            }
        }
        if (num_corrupted_bytes > 0) {
            asf_print(&asf_amem_print_ctrl,
                ASF_AMEM_CAT_FREE, ASF_AMEM_VERB_ERR,
                "*** ERROR: %d bytes corrupted before/behind buffer 0x%p, "
                "freed from %s, line %d\n",
                num_corrupted_bytes, user_ptr, file, line);
        }
    }
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_OOB_DIAG */

    if (inst->unlock_func) {
        inst->unlock_func(inst->lock);
    }
    inst->free_func(ptr);
#endif
}

asf_amem_size_t asf_amem_sbrk_private(
    asf_amem_instance_handle inst,
    asf_amem_size_t bytes)
{
    asf_amem_size_t old_limit;
    if ( ! inst ) {
        inst = &asf_amem_std;
    }
    old_limit = inst->limit_bytes;
    inst->limit_bytes = bytes;
    return old_limit;
}

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
void asf_amem_status_print(void)
{
    asf_amem_instance_handle inst = &asf_amem_std;

    while ( inst ) {
        if ( inst->name ) {
            asf_print(
                &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
                "asf_amem instance: %s\n", inst->name);
        } else {
            asf_print(
                &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
                "asf_amem instance: %p (anon)\n", inst);
        }
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "Limit of all allocations: %lld bytes\n",
            (long long) inst->limit_bytes);
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "Sum of all current allocations: %lld bytes\n",
            (long long) inst->total_bytes);

        if ( ! inst->cache_list ) {
            asf_print(
                &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
                "No pools of reserved memory currently exist.\n");
        } else {
            asf_amem_cache_handle cache_ptr = inst->cache_list;
            while ( cache_ptr ) {
                asf_amem_cache_status_print(cache_ptr);
                cache_ptr = cache_ptr->meta.next;
            }
        }
        inst = inst->next;
    }
}
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG */

asf_amem_instance_handle asf_amem_create(
    const char *name,
    asf_amem_size_t limit_bytes,
    asf_amem_alloc_fp alloc_func,
    asf_amem_free_fp free_func,
    void *osdev,
    asf_amem_lock_fp lock_func,
    asf_amem_unlock_fp unlock_func,
    void *lock,
    asf_amem_instance_handle allocator)
{
    asf_amem_instance_handle inst;

    /* allocate a new asf_amem instance (from standard memory) */
    if (allocator) {
        /*
         * The caller has specified another amem instance that will
         * jump-start this amem instance by allocating its object.
         */
        inst = amalloc_adv(allocator, sizeof(struct asf_amem_instance), NULL);
    } else {
        /*
         * Use the alloc_func and osdev that are provided for this new
         * amem instance's allocations to allocate the new amem object
         * itself.
         */
        inst = alloc_func(osdev, sizeof(struct asf_amem_instance));
    }
    if ( ! inst ) {
        return NULL;
    }

    inst->next = asf_amem_std.next;
    asf_amem_std.next = inst;

    inst->name = name;
    inst->limit_bytes = limit_bytes;
    inst->alloc_func = alloc_func;
    inst->free_func = free_func;
    inst->osdev = osdev;
    inst->lock_func = lock_func;
    inst->unlock_func = unlock_func;
    inst->lock = lock;

    inst->event_counter = 0;
    inst->total_bytes = 0;
    inst->cache_list = NULL;
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    inst->alloc_list = NULL;
    inst->leak.min_age_range = ASF_AMEM_LEAK_MIN_AGE_RANGE;
    inst->leak.lim_old_pct = ASF_AMEM_LEAK_LIM_OLD_PCT;
    inst->leak.lim_new_pct = ASF_AMEM_LEAK_LIM_NEW_PCT;
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */

    return inst;
}

enum asf_amem_status asf_amem_destroy(
    asf_amem_instance_handle inst,
    asf_amem_instance_handle destroyer)
{
    asf_amem_instance_handle list = &asf_amem_std;

    if (!inst) {
        return asf_amem_status_bad_handle;
    }

    /* confirm that this instance has no outstanding allocations */
    if (inst->total_bytes != 0) {
        return asf_amem_status_unfreed_elem;
    }

    /*
     * It would be nice to verify that the instance is no longer in
     * use before unlinking it and freeing it.  However, there's
     * no way to make sure that a user doesn't retain a stale handle
     * to the instance, beyond the simple check above that the
     * instance contains no outstanding allocations.
     * So we have to assume that the user has correctly stopped
     * using the allocation before calling asf_amem_destroy.
     */
    /*
     * It would be good to have a lock that is taken during
     * asf_amem_create, when linking instances into the list,
     * during asf_amem_allocs_print_private when traversing the
     * list of instances, and here, when unlinking instances from
     * the list.
     * In practice, these events should not overlap, so for now it
     * is acceptable to not introduce a global lock.
     */

    /* unlink this instance from the list of instances */
    while (list) {
        if (list->next == inst) {
            list->next = inst->next;
            break;
        } else {
            list = list->next;
        }
    }    

    /* delete the memory for this instance */
    if (destroyer) {
        /*
         * The caller has specified another amem instance that was used
         * to allocate the amem object for this amem instance, and thus
         * is also used to free this instance's amem object.
         */
        afree_adv(destroyer, inst);
    } else {
        /*
         * Use the free_func that was registered with this amem instance
         * to free the new amem object itself.
         */
        if (inst->free_func) {
            inst->free_func(inst);
        }
    }

    return asf_amem_status_success;
}

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS
void asf_amem_allocs_print_private(
    asf_amem_instance_handle inst,
    enum asf_amem_alloc_type which,
    int condense)
{
    if (! inst) {
        inst = &asf_amem_std;
    }

    while ( inst ) {
        asf_amem_cntr_t oldest;
        oldest = asf_amem_oldest_counter(inst);

        if ( inst->name ) {
            asf_print(
                &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
                "asf_amem instance: %s\n", inst->name);
        } else {
            asf_print(
                &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
                "asf_amem instance: %p (anon)\n", inst);
        }
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "Current counter value: %lld, oldest: %lld\n",
            inst->event_counter, oldest);
        /* heap-based allocations */
        if ( which == asf_amem_alloc_all  ||
             which == asf_amem_alloc_heap ||
             which == asf_amem_alloc_leaks ) {
            asf_amem_alloc_list_print(
                inst, inst->alloc_list, which,
                asf_amem_alloc_all | asf_amem_alloc_heap,
                oldest, condense);
        }

        /* print the relevant allocations in each pool */
        if ( which == asf_amem_alloc_all  ||
             which == asf_amem_alloc_cache ||
             which == asf_amem_alloc_leaks ) {
            asf_amem_cache_handle cache_ptr = inst->cache_list;
            while ( cache_ptr ) {
                asf_amem_cache_allocs_print(cache_ptr, which, oldest, condense);
                cache_ptr = cache_ptr->meta.next;
            }
        }
        inst = inst->next;
    }
}

int asf_amem_leak_min_age_range_private(asf_amem_instance_handle inst, int val)
{
    int old_val;
    if ( ! inst ) {
        inst = &asf_amem_std;
    }
    old_val = inst->leak.min_age_range;
    if ( val > 0 ) {
        inst->leak.min_age_range = val;
    }
    return old_val;
}

int asf_amem_leak_lim_old_pct_private(asf_amem_instance_handle inst, int val)
{
    int old_val;
    if ( ! inst ) {
        inst = &asf_amem_std;
    }
    old_val = inst->leak.lim_old_pct;
    if ( val >= 0 ) {
        inst->leak.lim_old_pct = val;
    }
    return old_val;
}

int asf_amem_leak_lim_new_pct_private(asf_amem_instance_handle inst, int val)
{
    int old_val;
    if ( ! inst ) {
        inst = &asf_amem_std;
    }
    old_val = inst->leak.lim_new_pct;
    if ( val >= 0 ) {
        inst->leak.lim_new_pct = val;
    }
    return old_val;
}

#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */

/*--- internal functions ---*/

static enum asf_amem_status asf_amem_cache_add(asf_amem_cache_handle handle, int add_elem)
{
    asf_amem_size_t bytes;
    struct asf_amem_chunk_header *buffer;
    struct asf_amem_elem_free_node *ptr;

    /* Return error code to notify caller no elements are added */
    if ( add_elem <= 0 ) {
        return asf_amem_status_bad_params;
    }

    bytes = add_elem *
        (handle->elem_bytes + ASF_AMEM_ELEM_PAD) +
        ASF_AMEM_CHUNK_PAD();
    buffer = amalloc_adv(handle->asf_amem_inst, bytes, NULL);
    if ( ! buffer ) {
        return asf_amem_status_malloc_fail; /* error */
    }

    /* add this chunk to the chunklist */
    buffer->next = handle->chunklist;
    handle->chunklist = buffer;

    /* add all the new elements to the freelist */
    ptr = (struct asf_amem_elem_free_node *)
        ASF_AMEM_MOVE_PAST_ELEM_HEADER(ASF_AMEM_MOVE_PAST_CHUNK_HEADER(buffer));
    handle->num_elem += add_elem;
    handle->free_elem += add_elem;
    while ( --add_elem > 0 ) {
        ptr->next = (struct asf_amem_elem_free_node *)
            (((char *) ptr) + (handle->elem_bytes + ASF_AMEM_ELEM_PAD));
        ptr = ptr->next;
    }
    ptr->next = handle->freelist;
    handle->freelist = (struct asf_amem_elem_free_node *)
        ASF_AMEM_MOVE_PAST_ELEM_HEADER(ASF_AMEM_MOVE_PAST_CHUNK_HEADER(buffer));
    return asf_amem_status_success;
}

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG

#if ASF_AMEM_NO_CHOP_FILENAME
#define asf_amem_chop_filename(name) name
#else
static const char *asf_amem_chop_filename(const char *name)
{
    const char *p = name;
    if (! name) {
        return name;
    }
    /* first advance to the end of the string */
    while (*p) p++;
    /* then back up until there's a ".." string */
    while (p != name) {
        if (p-name >= 1 && *p == '.' && *(p-1) == '.') {
            p++; /* go past the 2nd '.' char */
            while (*p == '/') p++; /* skip the next '/' char(s) */
            break;
        }
        p--;
    }
    return p;
}
#endif

static asf_amem_cntr_t asf_amem_oldest_counter(asf_amem_instance_handle inst)
{
    if ( inst ) {
        return 0; /* for now */
    }
    return 0;
}

static int asf_amem_alloc_is_leaked(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *p,
    asf_amem_cntr_t oldest,
    asf_amem_cntr_t newest)
{
    asf_amem_cntr_t rel_age, age_range;
    int percent;

    age_range = newest - oldest + 1;
    /* make sure there is enough data to make reasonable deductions */
    if ( age_range < inst->leak.min_age_range ) {
        return 0;
    }

    rel_age = p->counter - oldest;
//percent = rel_age * 100 / age_range; /* should guard against overflow */
//DBG
percent = 25;


    /*
     * Allocations that have not been around forever,
     * yet are not recent, are probably leaks.
     */
    if ( percent > inst->leak.lim_old_pct &&
         percent < inst->leak.lim_new_pct ) {
        return 1;
    }
    return 0;
}

static void asf_amem_leak_debug_init(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *ptr,
    const char *file,
    int line,
    asf_amem_size_t bytes,
    struct asf_amem_leak_debug **list)
{
    ptr->file = file;
    ptr->line = line;
    ptr->bytes = bytes;
    ptr->counter = inst->event_counter;
    ptr->prev = NULL;
    ptr->next = *list;
    if ( ptr->next ) {
        ptr->next->prev = ptr;
    }
    *list = ptr;
}

static void asf_amem_leak_debug_remove(
    struct asf_amem_leak_debug *ptr,
    struct asf_amem_leak_debug **list)
{
    if ( ptr->next ) {
        ptr->next->prev = ptr->prev;
    }
    if ( ptr->prev ) {
        ptr->prev->next = ptr->next;
    } else {
        *list = ptr->next;
    }
}

static void asf_amem_alloc_print(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *alloc,
    enum asf_amem_alloc_type which,
    unsigned whichMask,
    asf_amem_cntr_t oldest)
{
    if ( which & whichMask ||
         asf_amem_alloc_is_leaked(inst, alloc, oldest, inst->event_counter)) {
        const char *file = asf_amem_chop_filename(alloc->file);
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "  file %s,\n    line %d, event %lld, %lld bytes\n",
            file, alloc->line,
            (long long) alloc->counter, (long long) alloc->bytes);
    }
}

#define ASF_AMEM_LOCATION_SAMPLES 4
struct asf_amem_location_ages {
    int idx;
    asf_amem_cntr_t data[ASF_AMEM_LOCATION_SAMPLES];
};

struct asf_amem_location_sizes {
    int idx;
    asf_amem_size_t data[ASF_AMEM_LOCATION_SAMPLES];
};

struct asf_amem_location {
    struct asf_amem_location *next;
    const char *file;
    int line;
    int count;
    asf_amem_size_t total_bytes;
    struct asf_amem_location_ages  ages[2];  /* oldest, newest */
    struct asf_amem_location_sizes sizes[2]; /* smallest, largest */
};

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS
static struct asf_amem_location *asf_amem_location_find(
    struct asf_amem_location *list,
    const char *file,
    int line)
{
    while (list) {
        /*
         * A match means matching pointers to the file name string,
         * not having a matching but distinct string (strcmp).
         */
        if ( list->file == file && list->line == line ) {
            break;
        }
        list = list->next;
    }
    return list;
}

static int size_less_than(asf_amem_size_t a, asf_amem_size_t b) { return ( a < b ) ? 1 : 0; }
static int size_more_than(asf_amem_size_t a, asf_amem_size_t b) { return ( a > b ) ? 1 : 0; }

static void asf_amem_location_size_add(
    struct asf_amem_location_sizes *sizes,
    asf_amem_size_t size,
    int (*cmp)(asf_amem_size_t a, asf_amem_size_t b))
{
    int i, j;
    for ( i = 0 ; i < sizes->idx ; i++ ) {
        if ( cmp(size, sizes->data[i]) ) {
            j = ASF_AMEM_LOCATION_SAMPLES-1;
            if ( j > sizes->idx ) {
                j = sizes->idx;
            }
            while ( j > i ) {
                sizes->data[j] = sizes->data[j-1];
                j--;
            }
            break;
        }
    }
    if ( i < ASF_AMEM_LOCATION_SAMPLES ) {
        sizes->data[i] = size;
    }
    if ( sizes->idx < ASF_AMEM_LOCATION_SAMPLES ) {
        sizes->idx++;
    }
}

void asf_amem_location_sizes_print(struct asf_amem_location_sizes *sizes, int count)
{
    int i, lim1, lim2;
    if ( count >= ASF_AMEM_LOCATION_SAMPLES * 2 ) {
        lim1 = lim2 = ASF_AMEM_LOCATION_SAMPLES;
    } else {
        lim1 = count / 2;     /* round down */
        lim2 = (count+1) / 2; /* round up */
    }
    for ( i = 0 ; i < lim1 ; i++ ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "%ld, ", (long) sizes->data[i]);
    }
    if ( count > ASF_AMEM_LOCATION_SAMPLES * 2 ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "..., ");
    }
    sizes++;
    for ( i = lim2-1 ; i >= 0 ; i-- ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "%ld, ", (long) sizes->data[i]);
    }
}

static int age_less_than(asf_amem_cntr_t a, asf_amem_cntr_t b)
{
    return ( a < b ) ? 1 : 0;
}
static int age_more_than(asf_amem_cntr_t a, asf_amem_cntr_t b)
{
    return ( a > b ) ? 1 : 0;
}

static void asf_amem_location_age_add(
    struct asf_amem_location_ages *ages,
    asf_amem_cntr_t age,
    int (*cmp)(asf_amem_cntr_t a, asf_amem_cntr_t b))
{
    int i, j;
    for ( i = 0 ; i < ages->idx ; i++ ) {
        if ( cmp(age, ages->data[i]) ) {
            j = ASF_AMEM_LOCATION_SAMPLES-1;
            if ( j > ages->idx ) {
                j = ages->idx;
            }
            while ( j > i ) {
                ages->data[j] = ages->data[j-1];
                j--;
            }
            break;
        }
    }
    if ( i < ASF_AMEM_LOCATION_SAMPLES ) {
        ages->data[i] = age;
    }
    if ( ages->idx < ASF_AMEM_LOCATION_SAMPLES ) {
        ages->idx++;
    }
}

void asf_amem_location_ages_print(struct asf_amem_location_ages *ages, int count)
{
    int i, lim1, lim2;
    if ( count >= ASF_AMEM_LOCATION_SAMPLES * 2 ) {
        lim1 = lim2 = ASF_AMEM_LOCATION_SAMPLES;
    } else {
        lim1 = count / 2;     /* round down */
        lim2 = (count+1) / 2; /* round up */
    }
    for ( i = 0 ; i < lim1 ; i++ ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "%ld, ", (long) ages->data[i]);
    }
    if ( count > ASF_AMEM_LOCATION_SAMPLES * 2 ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "..., ");
    }
    ages++;
    for ( i = lim2-1 ; i >= 0 ; i-- ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "%ld, ", (long) ages->data[i]);
    }
}
#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS */

static void asf_amem_alloc_list_print(
    asf_amem_instance_handle inst,
    struct asf_amem_leak_debug *ptr,
    enum asf_amem_alloc_type which,
    unsigned whichMask,
    asf_amem_cntr_t oldest,
    int condense)
{
    if ( ! condense ) {
        whichMask = 0; /* suppress compiler warning about unused vars */
        while ( ptr ) {
            asf_amem_alloc_print(
                inst, ptr, which,
                asf_amem_alloc_all | asf_amem_alloc_cache, oldest);
            ptr = ptr->next;
        }
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_PRINTOUTS
    } else {
        /*
         * Rather than printing out each allocation, print out one line for
         * each allocation location.
         * Include a count of how many outstanding allocations came from each
         * location, and the total size of each location's allocations.
         * Include a summary / sample of the ages and sizes of the individual
         * allocations from this each location.
         */
        struct asf_amem_location *locations = NULL;
        struct asf_amem_location *loc = NULL;
        while ( ptr ) {
            if ( ! (which & whichMask) &&
                 ! asf_amem_alloc_is_leaked(
                       inst, ptr, oldest, inst->event_counter) ) {
                ptr = ptr->next;
                continue;
            }
            loc = asf_amem_location_find(locations, ptr->file, ptr->line);
            if ( ! loc ) {
                /* new location - add it to the list of locations */
                loc = amalloc_adv(
                    &asf_amem_std, sizeof(struct asf_amem_location), NULL);
                if ( ! loc ) {
                    break;
                }
                loc->file = ptr->file;
                loc->line = ptr->line;
                loc->next = locations;
                loc->count = 0;
                loc->total_bytes = 0;
                loc->ages[0].idx = 0;
                loc->ages[1].idx = 0;
                loc->sizes[0].idx = 0;
                loc->sizes[1].idx = 0;
                locations = loc;
            }
            loc->count++;
            loc->total_bytes += ptr->bytes;

            asf_amem_location_size_add(
                &loc->sizes[0], ptr->bytes, size_less_than);
            asf_amem_location_size_add(
                &loc->sizes[1], ptr->bytes, size_more_than);
            asf_amem_location_age_add(
                &loc->ages[0], ptr->counter, age_less_than);
            asf_amem_location_age_add(
                &loc->ages[1], ptr->counter, age_more_than);
            ptr = ptr->next;
        }
        /* print information about each location (unless there was an error) */
        if ( loc ) {
            loc = locations;
            while ( loc ) {
                const char *file = asf_amem_chop_filename(loc->file);
                asf_print(
                    &asf_amem_print_ctrl,
                    ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
                    "  count: %d, total bytes: %lld,\n"
                    "  file: %s,\n  line: %d\n",
                    loc->count, (long long) loc->total_bytes,
                    file, loc->line);
                asf_print(
                    &asf_amem_print_ctrl,
                    ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO, "    sizes: ");
                asf_amem_location_sizes_print(loc->sizes, loc->count);
                asf_print(
                    &asf_amem_print_ctrl,
                    ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO, "\n");
                asf_print(
                    &asf_amem_print_ctrl,
                    ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO, "    ages: ");
                asf_amem_location_ages_print(loc->ages, loc->count);
                asf_print(
                    &asf_amem_print_ctrl,
                    ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO, "\n");
                loc = loc->next;
            }
        }
        /* free the list of locations */
        while ( locations ) {
            loc = locations->next;
            afree_adv(&asf_amem_std, locations);
            locations = loc;
        }
#endif
    }
}

static void asf_amem_cache_allocs_print(
    asf_amem_cache_handle handle,
    enum asf_amem_alloc_type which,
    asf_amem_cntr_t oldest,
    int condense)
{
    const char *name;

    name = handle->meta.name ? handle->meta.name : "(anon)";
    asf_print(
        &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
        "Memory pool \"%s\" allocations:\n", name);
    asf_amem_alloc_list_print(
        handle->asf_amem_inst, handle->meta.alloc_list,
        which, asf_amem_alloc_all | asf_amem_alloc_cache,
        oldest, condense);
}

#endif /* ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG */

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
static void asf_amem_cache_status_print(struct asf_amem_cache *p)
{
    const char *name;

    name = p->meta.name ? p->meta.name : "(anon)";
    asf_print(
        &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
        "Memory pool \"%s\", created at file %s,\n  line %d\n",
        name, p->meta.file, p->meta.line);
    asf_print(
        &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
        "  Reserved %d elements of %lld bytes each"
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
        " (%lld bytes requested)"
#endif
        ".\n",
        p->num_elem, (long long) p->elem_bytes
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
        , (long long) p->meta.req_bytes
#endif
        );
    asf_print(
        &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
        "  Total reserved memory, including header overhead: %d bytes\n",
        p->num_elem * (p->elem_bytes + ASF_AMEM_ELEM_PAD));
    asf_print(
        &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
        "  %d elements are in use; %d are unused\n",
        p->num_elem - p->free_elem, p->free_elem);
    if ( p->num_elem == p->max_elem ) {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "  Pool has already reached its memory reservation limit.\n");
    } else {
        asf_print(
            &asf_amem_print_ctrl, ASF_AMEM_CAT_STATUS, ASF_AMEM_VERB_INFO,
            "  Will try to expand pool up to %d elements if needed.\n",
            p->max_elem);
    }
}
#endif
