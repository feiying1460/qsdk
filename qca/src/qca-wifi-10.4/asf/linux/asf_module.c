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
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>

#include "asf_amem.h"
#include "asf_print.h"

MODULE_AUTHOR("Atheros Communications, Inc.");
MODULE_DESCRIPTION("Atheros Device Module");
//#ifdef MODULE_LICENSE
MODULE_LICENSE("Proprietary");
//#endif

static int __init init_asf(void) { return 0; }
module_init(init_asf);

static void __exit exit_asf(void) { }
module_exit(exit_asf);


/* API functions from asf_amem */
EXPORT_SYMBOL(asf_amem_setup);
EXPORT_SYMBOL(asf_amem_create);
EXPORT_SYMBOL(asf_amem_destroy);
EXPORT_SYMBOL(amalloc_private);
EXPORT_SYMBOL(afree_private);
EXPORT_SYMBOL(asf_amem_cache_create_private);
EXPORT_SYMBOL(asf_amem_cache_alloc_private);
#if ASF_AMEM_SUPPORT >= 3
EXPORT_SYMBOL(asf_amem_status_print);
#endif
#if ASF_AMEM_SUPPORT >= 4
EXPORT_SYMBOL(asf_amem_allocs_print_private);
EXPORT_SYMBOL(asf_amem_leak_min_age_range_private);
EXPORT_SYMBOL(asf_amem_leak_lim_old_pct_private);
EXPORT_SYMBOL(asf_amem_leak_lim_new_pct_private);
#endif


/* API functions and global variables from asf_print */
EXPORT_SYMBOL(asf_print_setup);
EXPORT_SYMBOL(asf_vprint_private);
#if ! ASF_PRINT_INLINE
EXPORT_SYMBOL(asf_print_category_private);
EXPORT_SYMBOL(asf_vprint_category_private);
#endif
EXPORT_SYMBOL(asf_print_private);
EXPORT_SYMBOL(AsfPrintCtrlShared);
EXPORT_SYMBOL(asf_print_ctrl_register_private);
EXPORT_SYMBOL(asf_print_ctrl_unregister_private);
EXPORT_SYMBOL(asf_print_mask_set);
EXPORT_SYMBOL(asf_print_mask_set_by_name_private);
EXPORT_SYMBOL(asf_print_mask_set_by_bit_name_private);
EXPORT_SYMBOL(asf_print_verb_set_by_name_private);
EXPORT_SYMBOL(asf_print_get_namespaces_private);
EXPORT_SYMBOL(asf_print_get_bit_specs_private);
EXPORT_SYMBOL(asf_print_new);
EXPORT_SYMBOL(asf_print_destroy);
