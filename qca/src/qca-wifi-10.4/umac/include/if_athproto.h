/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#ifndef _NET_IF_ATH_PROTO_H_
#define _NET_IF_ATH_PROTO_H_

/*
 * Atheros proprietary protocol info.
 */

/*
 * Atheros proprietary SuperG defines.
 */

#define ATH_ETH_TYPE  0x88bd
#define ATH_SNAP_ORGCODE_0 0x00
#define ATH_SNAP_ORGCODE_1 0x03
#define ATH_SNAP_ORGCODE_2 0x7f

struct athl2p_tunnel_hdr {
#if (AH_BYTE_ORDER == AH_LITTLE_ENDIAN)
	u_int32_t  offset	: 11,
	seqNum       		: 11,
	optHdrLen32  		: 2,
	frameType    		: 2,
	proto        		: 6;
#else /* big endian */
	u_int32_t  proto	: 6,
	frameType    		: 2,
	optHdrLen32  		: 2,
	seqNum       		: 11,
	offset       		: 11;
#endif
} __packed;

/*
 * Reserve enough buffer header length to avoid reallocation on fast-frame
 * rx and tx.
 */
#define USE_HEADERLEN_RESV 1

/*
 * Atheros proprietary AMSDU defines.
 */
#ifdef ATH_AMSDU
#define AMSDU_TIMEOUT 15
#define AMSDU_MAX_SUBFRM_LEN 100
#define AMSDU_BUFFER_HEADROOM 64
#ifdef ATH_SUPPORT_HTC
#define AMSDU_MAX_BUFFER_SIZE 1568
#else
// HACK !!! MacOS and NetBSD use a max size of 2048 bytes.
#define AMSDU_MAX_BUFFER_SIZE 2048 
#endif
// AMSDU_MAX_LEN of 1600 was arrived at after experiments in OTA and Azimuth testing.
// If this needs to be changed, please make sure that perf is not compromised.
#define AMSDU_MAX_LEN 1600
#endif

#endif /* _NET_IF_ATH_PROTO_H_ */
