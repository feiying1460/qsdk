/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef __IEEE80211_RDX_H__
#define __IEEE80211_RDX_H__

#include <osdep.h>

#define ETH_ALEN 6

#define ATH_MITBL_NONE	0x0000
#define ATH_MITBL_IPV4	0x0001
#define ATH_MITBL_IPV6	0x0002

typedef struct mi_node { /* MAC - IP Node */

#if MI_TABLE_AS_TREE
	struct mi_node	*parent,
			*left,
			*right;
#else
#	define mi_node_is_free(n)	((n)->ip_ver == ATH_MITBL_NONE)
#	define mi_node_free(n)	do { (n)->ip_ver = ATH_MITBL_NONE; } while(0)
#endif

	u_int8_t	h_dest[ETH_ALEN],
			len,
			ip_ver,
			ip[16];	/* v4 or v6 ip addr */
} mi_node_t;

#define minode_ip_len(n)	(((n)->ip_ver == ATH_MITBL_IPV4) ? 4 : 16)
#define mi_ip_len(n)		(((n) == ATH_MITBL_IPV4) ? 4 : 16)

#ifdef EXTAP_DEBUG
#	define EXTAP_DBG_PARM	const char *f, int l,
#else
#	define EXTAP_DBG_PARM	/* */
#endif

mi_node_t *mi_tbl_add(EXTAP_DBG_PARM mi_node_t **, u_int8_t *, u_int8_t *, int);
u_int8_t *mi_tbl_lkup(EXTAP_DBG_PARM mi_node_t *, u_int8_t *, int);
void mi_tbl_del(EXTAP_DBG_PARM mi_node_t **, u_int8_t *, int);

#endif /* __IEEE80211_RDX_H__ */
