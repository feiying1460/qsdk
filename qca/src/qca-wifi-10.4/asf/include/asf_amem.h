/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef ASF_AMEM_H
#define ASF_AMEM_H

/*
 * ASF_AMEM_SUPPORT:
 *   PASS_THRU (1):
 *      most basic level of support - amem is just a thin cover on top
 *      of the underlying memory allocation functions.
 *   BASIC_MGMT (2):
 *      basic management - use allocation headers to keep a running total
 *      of allocated memory, provide memory pool freelists, allow
 *      pre-allocation and allocation limitation
 *   SIMPLE_DIAG (3):
 *      basic diagnostics - summarize current allocations
 *   ADV_DIAG (4):
 *      advanced diagnostics - show individual current allocations, diagnose
 *      which allocations appear to be memory leaks
 *   PRINTOUTS (5):
 *      advanced print formatting - smart printouts that filter individual
 *      allocations display to just show the most relevant and only
 *      summarize the rest, to avoid spewing an excessive printout.
 *   FREE_DIAG (6):
 *      check for duplicate frees
 *   OOB_DIAG (7):
 *      check for acesses before or beyond the allocated buffer
 *   FAKE_FAIL (8);
 *      make memory allocation requests artificially fail, based on
 *      specified failure probability profiles
 */
#define ASF_AMEM_SUPPORT_PASS_THRU    1
#define ASF_AMEM_SUPPORT_BASIC_MGMT   2
#define ASF_AMEM_SUPPORT_SIMPLE_DIAG  3
#define ASF_AMEM_SUPPORT_ADV_DIAG     4
#define ASF_AMEM_SUPPORT_PRINTOUTS    5
#define ASF_AMEM_SUPPORT_FREE_DIAG    6
#define ASF_AMEM_SUPPORT_OOB_DIAG     7
#define ASF_AMEM_SUPPORT_FAKE_FAIL    8

#ifndef ASF_AMEM_SUPPORT
    /* by default, compile minimal version of amem */
    #define ASF_AMEM_SUPPORT ASF_AMEM_SUPPORT_PASS_THRU
#endif

#include "qdf_types.h" /* qdf_size_t, __ahdecl */

#ifndef NULL
#define NULL ((void *) 0)
#endif

typedef qdf_size_t asf_amem_size_t;

enum asf_amem_status {
    asf_amem_status_success = 0,
    asf_amem_status_bad_handle,
    asf_amem_status_bad_params,
    asf_amem_status_unfreed_elem,
    asf_amem_status_malloc_fail,
    asf_amem_status_duplicate_free,
    asf_amem_status_corruption,

    asf_amem_status_num_values
};

typedef struct asf_amem_cache *asf_amem_cache_handle;

typedef void *(*asf_amem_alloc_fp)(void *osdev, asf_amem_size_t bytes);
typedef void (*asf_amem_free_fp)(void *ptr);

typedef void (*asf_amem_lock_fp)(void *lock);
typedef void (*asf_amem_unlock_fp)(void *lock);

typedef void (*asf_amem_constructor_fp)(void *ptr, asf_amem_size_t bytes);

/*--- standard API functions -----------------------------------------------*/

/* asf_amem_setup:
 * Register memory allocation and deallocation functions for the default
 * asf_amem instance.  These could be either kernel functions, a la
 * kmalloc and kfree, or regular functions a la malloc and free.
 * (Technically, kmalloc, kfree, malloc, and free would all need a wrapper
 * that has a osdev initial argument.)
 * Along with the alloc/free functions, register a "osdev" handle that is
 * passed as an initial argument to the alloc function.
 * Inputs:
 *   - alloc_func: Function to allocate memory of the type managed by the
 *     default asf_amem instance.
 *   - free_func: Function to free memory of the type managed by the
 *     default asf_amem instance
 *   - osdev: Handle to an operating system object that is passed as an
 *     initial argument to the alloc function.
 *   - lock_func: Function to provide mutual exclusion between calls to
 *     asf_amem functions from different execution contexts
 *   - unlock_func: Function to unlock mutual exclusion guard after
 *     critical section.
 *   - lock: Handle to an operating system mutual exclusion lock object.
 *
 * If the alloc and free function pointers have been set to a non-NULL
 * value already, asf_amem_setup will ignore new values for these
 * function pointers, unless the new values are NULL.
 * Thus, a 2nd call to asf_amem_setup will have no effect, unless it
 * sets the function pointers to NULL, so a 3rd call to asf_amem_setup
 * can reprogram the function pointers.
 * The asf_amem_reset macro can be used to undo an initial call to
 * asf_amem_setup, so a subsequent asf_amem_setup call can register
 * different function pointers / OS context object / lock object.
 */
extern void
asf_amem_setup(
    asf_amem_alloc_fp alloc_func,
    asf_amem_free_fp free_func,
    void *osdev,
    asf_amem_lock_fp lock_func,
    asf_amem_unlock_fp unlock_func,
    void *lock);

/* asf_amem_reset:
 * Erase the function pointers registered by a prior call to
 * asf_amem_setup, so a subsequent call to asf_amem_setup can
 * register different function pointers.
 */
#define asf_amem_reset() \
    asf_amem_setup(NULL, NULL, NULL, NULL, NULL, NULL)

/* asf_amem_cache_create:
 * Set up a memory pool of fixed-size elements, and return a handle
 * to use as a reference to the memory pool.  Optionally fill the
 * pool with a specified number of elements.
 * Inputs:
 *   - name: Optional name to identify memory pool in monitoring / debug
 *     printouts.  NULL is acceptable if no name is desired.
 *   - elem_bytes: How large are the elements in the pool.
 *   - min_elems:  How many elements to pre-allocate while creating the pool.
 *   - max_elems:  The maximum number of elements to allocate in the pool.
 *     To allow the pool to grow without bound, use max_elems == 0.
 * Returns:
 *     handle to memory pool on success, NULL on failure
 */
#define asf_amem_cache_create(name, elem_bytes, min_elems, max_elems)   \
    asf_amem_cache_create_private(                                      \
        __FILE__, __LINE__, name, elem_bytes, min_elems, max_elems,     \
        0, NULL)

/* asf_amem_cache_alloc:
 * Return an element from the specified memory pool.  If the pool has no free
 * elements but is not at its allocation limit, a new chunk of elements will
 * be added to the memory pool.
 * The allocated element is not initialized.
 * Inputs:
 *   - handle: reference to the memory pool (from asf_amem_cache_create)
 * Returns:
 *     a properly-aligned element from the memory pool on success,
 *     NULL on failure
 */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    #define asf_amem_cache_alloc(handle) \
        asf_amem_cache_alloc_private(__FILE__, __LINE__, handle)
#else
    #define asf_amem_cache_alloc(handle) asf_amem_cache_alloc_private(handle)
#endif

/* asf_amem_cache_free:
 * Return an element to the memory pool it came from.
 * This does not return the element's memory to the operating system -
 * the memory pool retains the element in its freelist.
 * (asf_amem_cache_shrink can be used to return the memory pool's unused
 * elements to the operating system.)
 * Inputs:
 *   - handle: reference to the memory pool the element is being returned to
 *   - ptr: address of the element being returned to the memory pool
 * Returns:
 *     asf_amem_status_success on success, status error code on failure
 */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    #define asf_amem_cache_free(handle, ptr) \
        asf_amem_cache_free_private(handle, __FILE__, __LINE__, ptr)
#else
    #define asf_amem_cache_free(handle, ptr) \
        asf_amem_cache_free_private(handle, ptr)
#endif

/* asf_amem_cache_shrink:
 * Attempt to return a specified number of elements from the memory pool's
 * freelist to the operating system.
 * Only chunks whose elements are all free are deleted.
 * Inputs:
 *   - handle: reference to the memory pool the element is being returned to
 *   - elems_to_free: target number of elements to return from the memory
 *     pool's freelist to the operating system.  If the memory pool's
 *     chunk_elem parameter is not 1, it may not be possible to free exactly
 *     the requested number of elements.  In this case, asf_amem_cache_shrink
 *     will free up to chunk_elems-1 elements more than the requested
 *     number.
 *     Memory pool chunks can only be returned to the operating system if
 *     all their elements are on the memory pool's freelist.
 *     If elems_to_free <= 0, all memory pool chunks which have no elements
 *     allocated to the memory pool user will be returned to the operating
 *     system.
 * Returns:
 *     The actual number of elements returned to the operating system.
 */
extern int
asf_amem_cache_shrink(asf_amem_cache_handle, int elems_to_free);

/* asf_amem_cache_destroy:
 * Delete the specified memory pool.
 * All memory pool elements must be returned to the memory pool via
 * asf_amem_cache_free to successfully destroy the memory pool.
 * Calling asf_amem_cache_destroy on a memory pool with outstanding element
 * allocations is not harmful, but will result in the pool not being
 * destroyed.
 * Inputs:
 *   - handle: reference to the memory pool the element is being returned to
 *   - ptr: address of the element being returned to the memory pool
 * Returns:
 *     asf_amem_status_success on success, status error code on failure
 */
extern enum asf_amem_status asf_amem_cache_destroy(asf_amem_cache_handle h);

/* amalloc:
 * Allocate the specified amount of memory, as long as the (optional)
 * asf_amem heap limit is not exceeded.
 * The allocated memory is not initialized.
 * Inputs:
 *   - bytes: allocation size
 * Returns:
 *     a properly-aligned buffer of the requested size on success,
 *     NULL on failure
 */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    #define amalloc(bytes) \
        amalloc_private(NULL, __FILE__, __LINE__, bytes, NULL)
#else
    #define amalloc(bytes) amalloc_private(NULL, bytes, NULL)
#endif

/* afree:
 * Free the specified buffer.
 * Inputs:
 *   - ptr: the buffer being freed
 */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    #define afree(ptr) afree_private(NULL, __FILE__, __LINE__, ptr)
#else
    #define afree(ptr) afree_private(NULL, ptr)
#endif

/* asf_amem_sbrk
 * Set a new limit for the total number of bytes asf_amem will allow in
 * outstanding allocations.
 * A value of 0 indicates that there is no limit on asf_amem's allocation,
 * as long as the operating system itself continues to provide memory
 * to asf_amem.
 * Inputs:
 *   - bytes: new limit for total current allocations
 * Returns:
 *     old total current allocations limit
 */
#define asf_amem_sbrk(bytes) asf_amem_sbrk_private(NULL, bytes)

/*--- advanced API functions -------------------------------------------------
 * These functions are for "power users" who want to use asf_amem to manage
 * memory allocations for multiple types of memory, each with its own
 * functions to allocate / free memory, and its own limit for total
 * allocations.
 */

/*
 * Provide a forward declaration of asf_amem_instance to create a
 * asf_amem_instance_handle opaque pointer to asf_amem_instance.
 */
struct asf_amem_instance;
typedef struct asf_amem_instance *asf_amem_instance_handle;

/* asf_amem_create:
 * Create a new asf_amem instance to manage a particular type of memory.
 * Inputs:
 *   - name: An optional name to distinguish this asf_amem instance from
 *     others in debug printouts.  A NULL value is acceptable.
 *   - limit_bytes: the maximum total number of bytes of outstanding
 *     allocations to allow (or 0 for no limit)
 *   - alloc_func: Function to allocate memory of the type managed by
 *     this asf_amem instance.  This allows asf_amem to be used to manage
 *     different types of memory, e.g. kernel memory, user memory, or
 *     uncacheable memory.
 *   - free_func: function to free memory of the type managed by this
 *     asf_amem instance
 *   - osdev: Handle to an operating system object that is passed as an
 *     initial argument to the alloc function.
 *   - lock_func: Function to provide mutual exclusion between calls to
 *     asf_amem functions from different execution contexts
 *   - unlock_func: Function to unlock mutual exclusion guard after
 *     critical section.
 *   - lock: Handle to an operating system mutual exclusion lock object.
 *   - allocator: An optional handle to another amem instance to use for
 *     allocating the new instance.  If allocator is NULL, the free_func
 *     and osdev args will be used to allocate the new amem object.
 * Returns:
 *     a handle to the new asf_amem instance on success, or NULL on failure
 */
extern asf_amem_instance_handle
asf_amem_create(
    const char *name,
    asf_amem_size_t limit_bytes,
    asf_amem_alloc_fp alloc_func,
    asf_amem_free_fp free_func,
    void *osdev,
    asf_amem_lock_fp lock_func,
    asf_amem_unlock_fp unlock_func,
    void *lock,
    asf_amem_instance_handle allocator);

/* asf_amem_destroy:
 * Delete an asf_amem instance.
 * The deletion will fail if the asf_amem instance has outstanding
 * allocations.
 * Inputs:
 *   - handle: A reference to the asf_amem instance to be deleted
 *   - destroyer: An optional handle to another amem instance to use for
 *     deleting the amem object.  If destroyer is NULL, the free_func
 *     that was registered with the amem object being deleted will be
 *     used for the deletion.
 * Returns:
 *     asf_amem_status_success on success, status error code on failure
 */
extern enum asf_amem_status asf_amem_destroy(
    asf_amem_instance_handle handle,
    asf_amem_instance_handle destroyer);

/* asf_amem_cache_create_adv:
 * Advanced version of asf_amem_cache_create.
 * The initial arguments are the same as asf_amem_cache_create, and the
 * following arguments are added:
 *   - chunk_elems:  How many elements to add to the memory pool at once.
 *     This parameter should be set to 1 if there is any intent to shrink
 *     the memory pool with asf_amem_cache_shrink.  (Otherwise, fragmentation
 *     may limit the ability to shrink the memory pool.)
 */
#define asf_amem_cache_create_adv(                                          \
    name, elem_bytes, min_elems, max_elems, chunk_elems, asf_amem_instance) \
        asf_amem_cache_create_private(                                      \
            __FILE__, __LINE__, name, elem_bytes, min_elems, max_elems,     \
            chunk_elems, asf_amem_instance)

/* amalloc_adv:
 * Advanced version of amalloc.
 * Specify a particular asf_amem handle to amalloc rather than using the default.
 * This allows amalloc_adv() to be used with special memory allocation
 * functions other than the default used by amalloc().
 * Inputs:
 *   - handle: reference to a asf_amem instance (returned by asf_amem_create),
 *     which contains a custom memory allocation function.
 *     Supplying NULL for this argument causes the default amem instance
 *     to be used to perform the allocation.
 *   - bytes: allocation size
 *   - constructor: a "void (*)(void *p, asf_amem_size_t bytes)" function
 *     pointer that will be applied to the memory allocated by amalloc_adv.
 *     NULL can be supplied for this argument to avoid initializing the
 *     newly allocated memory.
 * Returns:
 *     a properly-aligned buffer of the requested size from the memory type
 *     associated with the specified asf_amem instance on success, or
 *     NULL on failure
 */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    #define amalloc_adv(handle, bytes, constructor) \
        amalloc_private(handle, __FILE__, __LINE__, bytes, constructor)
#else
    #define amalloc_adv(handle, bytes, constructor) \
        amalloc_private(handle, bytes, constructor)
#endif

/* afree_adv:
 * Advanced version of afree.
 * Specify a particular asf_amem handle rather than using the default.
 * This allows use of special alloc/free functions for memory types
 * other than the default handled by amalloc()/afree().
 * Inputs:
 *   - handle: reference to a asf_amem instance (returned by asf_amem_create),
 *     which contains a custom memory free function
 *   - ptr: the buffer being freed
 */ 
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    #define afree_adv(handle, ptr) \
        afree_private(handle, __FILE__, __LINE__, ptr)
#else
    #define afree_adv(handle, ptr) afree_private(handle, ptr)
#endif

/* asf_amem_sbrk_adv
 * Advanced version of asf_amem_sbrk.
 * Specify a particular asf_amem handle rather than using the default.
 * This allows different total memory allocation limits to be used for
 * standard vs. special memory types.
 * Inputs:
 *   - handle: reference to a asf_amem instance (returned by asf_amem_create),
 *     which has its independent total memory allocation limit
 *   - bytes: new limit for total current allocations
 * Returns:
 *     old total current allocations limit for this asf_amem instance
 */
#define asf_amem_sbrk_adv(handle, bytes) asf_amem_sbrk_private(handle, bytes)


/*--- debug API functions ----------------------------------------------------
 * These functions are part of the asf_amem API.  However, they are only
 * effective if asf_amem has been compiled with a high enough level of
 * ASF_AMEM_SUPPORT.
 * Otherwise, these functions will silenty do nothing.
 */

enum asf_amem_alloc_type {
    asf_amem_alloc_all   = 0x1, /* both heap and pool-based allocations */
    asf_amem_alloc_heap  = 0x2, /* all heap-based allocations (but not pool) */
    asf_amem_alloc_cache = 0x4, /* all pool-based allocations (but not heap) */
    asf_amem_alloc_leaks = 0x8, /* heap and pool allocs that look like leaks */
};

/**** ASF_AMEM_SUPPORT == ASF_AMEM_SUPPORT_SIMPLE_DIAG
 * basic monitoring code that has little or no cost
 */

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
    void asf_amem_status_print(void);
#else
    #define asf_amem_status_print()
#endif

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_SIMPLE_DIAG
    const char *asf_amem_status_to_string(enum asf_amem_status status);
#else
    #define asf_amem_status_to_string(status) ""
#endif

/**** ASF_AMEM_SUPPORT == ASF_AMEM_SUPPORT_ADV_DIAG:
 * monitoring code that has a moderate cycles and/or mem overhead
 */
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    #define asf_amem_allocs_print(which, condense) \
        asf_amem_allocs_print_private(NULL, which, condense)

    #define asf_amem_leak_min_age_range(val) \
         asf_amem_leak_min_age_range_private(NULL, val)
    #define asf_amem_leak_lim_old_pct(val)   \
         asf_amem_leak_lim_old_pct_private(NULL, val)
    #define asf_amem_leak_lim_new_pct(val)   \
         asf_amem_leak_lim_new_pct_private(NULL, val)

    #define asf_amem_leak_min_age_range_adv(inst, val) \
         asf_amem_leak_min_age_range_private(inst, val)
    #define asf_amem_leak_lim_old_pct_adv(inst, val)   \
         asf_amem_leak_lim_old_pct_private(inst, val)
    #define asf_amem_leak_lim_new_pct_adv(inst, val)   \
         asf_amem_leak_lim_new_pct_private(inst, val)
#else
    #define asf_amem_allocs_print(which, condense)
    #define asf_amem_leak_min_age_range(val) -1
    #define asf_amem_leak_lim_old_pct(val)   -1
    #define asf_amem_leak_lim_new_pct(val)   -1
#endif

/*--- private functions ------------------------------------------------------
 * These functions are not actually part of the API, but must be included
 * in the header file, since the API includes macros that refer to these
 * "private" functions.
 */

/*
 * Don't use asf_amem_cache_create_private() directly;
 * use asf_amem_cache_create() (or asf_amem_cache_create_adv) instead.
 */
extern asf_amem_cache_handle
asf_amem_cache_create_private (
    const char *file,
    int line,
    const char *name,
    asf_amem_size_t elem_bytes,
    int min_elems,
    int max_elems,
    int chunk_elems,
    asf_amem_instance_handle inst);

/*
 * Don't use asf_amem_cache_alloc_private() directly;
 * use asf_amem_cache_alloc() instead.
 */
extern void *
asf_amem_cache_alloc_private(
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    const char *file, int line,
#endif
    asf_amem_cache_handle handle);

/*
 * Don't use asf_amem_cache_free_private() directly;
 * use asf_amem_cache_free() instead.
 */
extern enum asf_amem_status
asf_amem_cache_free_private(
    asf_amem_cache_handle h,
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    const char *file, int line,
#endif
    void *ptr);

/*
 * Don't use amalloc_private() directly;
 * use amalloc() (or amalloc_adv) instead.
 */
extern void * __ahdecl
amalloc_private(
    asf_amem_instance_handle inst,
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
    const char *file, int line,
#endif
    asf_amem_size_t user_bytes,
    asf_amem_constructor_fp contructor);

/*
 * Don't use afree_private() directly;
 * use afree() (or afree_adv) instead.
 */
extern void __ahdecl 
afree_private(
    asf_amem_instance_handle inst,
#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_FREE_DIAG
    const char *file, int line,
#endif
    void *user_ptr);

/*
 * Don't use asf_amem_sbrk_private directly;
 * Use asf_amem_sbrk (or asf_amem_sbrk_adv) instead.
 */
extern asf_amem_size_t asf_amem_sbrk_private(
    asf_amem_instance_handle inst,
    asf_amem_size_t bytes);

#if ASF_AMEM_SUPPORT >= ASF_AMEM_SUPPORT_ADV_DIAG
extern void asf_amem_allocs_print_private(
    asf_amem_instance_handle inst,
    enum asf_amem_alloc_type which, int condense);
int asf_amem_leak_min_age_range_private(
    asf_amem_instance_handle inst, int val);
int asf_amem_leak_lim_old_pct_private(
    asf_amem_instance_handle inst, int val);
int asf_amem_leak_lim_new_pct_private(
    asf_amem_instance_handle inst, int val);
#endif

#endif /* ASF_AMEM_H */
