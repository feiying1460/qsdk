/* Copyright (c) 2017  Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc
 * Notifications and licenses are retained for attribution purposes only
 */

/*
 * Copyright (c) 2008, Atheros Communications Inc.
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

#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <err.h>
#include <unistd.h>

#include "if_athioctl.h"
#define _LINUX_TYPES_H
/*
 * Provide dummy defs for kernel types whose definitions are only
 * provided when compiling with __KERNEL__ defined.
 * This is required because ah_internal.h indirectly includes
 * kernel header files, which reference these data types.
 */
#define __be64 u_int64_t
#define __le64 u_int64_t
#define __be32 u_int32_t
#define __le32 u_int32_t
#define __be16 u_int16_t
#define __le16 u_int16_t
#define __be8  u_int8_t
#define __le8  u_int8_t
typedef struct {
        volatile int counter;
} atomic_t;

#ifndef __KERNEL__
  typedef __kernel_loff_t             loff_t;
#endif

#include "ah.h"
#include "dfs_ioctl.h"
#include "ah_devid.h"
#include "ah_internal.h"
#include "ar5212/ar5212.h"
#include "ar5212/ar5212reg.h"

#ifndef ATH_DEFAULT
#define	ATH_DEFAULT	"wifi0"
#endif

struct radarhandler {
	int	s;
	struct ath_diag atd;
};

static int
radarShowNol(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_SHOW_NOL | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
static int
radarShowNolHistory(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_SHOW_NOLHISTORY | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}
#endif

static int
radarSetDebugLevel(struct radarhandler *radar, u_int32_t level)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_SET_DEBUG_LEVEL | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &level;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
    return 0;
}
static int
radarIgnoreCAC(struct radarhandler *radar, u_int32_t value)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_IGNORE_CAC | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &value;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
    return 0;
}
static int
radarSetNOLTimeout(struct radarhandler *radar, u_int32_t value)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_SET_NOL_TIMEOUT | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &value;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}

static int
radarSetFalseRssiThres(struct radarhandler *radar, u_int32_t level)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_SET_FALSE_RSSI_THRES | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &level;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}
static int
radarSetPeakMag(struct radarhandler *radar, u_int32_t level)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_SET_PEAK_MAG | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &level;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}
static int
radarGetCacValidTime(struct radarhandler *radar)
{
    u_int32_t result = 0;
    struct ifreq ifr;

    radar->atd.ad_id = DFS_GET_CAC_VALID_TIME | ATH_DIAG_DYN;
    radar->atd.ad_in_data = NULL;
    radar->atd.ad_in_size = 0;
    radar->atd.ad_out_data = (void *) &result;
    radar->atd.ad_out_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;
    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
          err(1, radar->atd.ad_name);

    /* clear references to local variables */
    radar->atd.ad_out_data = NULL;

    return(result);
}
static int
radarSetCacValidTime(struct radarhandler *radar, u_int32_t level)
{
	u_int32_t result;
   	 struct ifreq ifr;

	radar->atd.ad_id = DFS_SET_CAC_VALID_TIME | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &level;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}
static int
radarDisableFFT(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_DISABLE_FFT | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
    return 0;
}

static int
radarEnableFFT(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_ENABLE_FFT | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}
static int
radarDisableDetect(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_DISABLE_DETECT | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}

static int
radarEnableDetect(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_ENABLE_DETECT | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}

static int
radarBangRadar(struct radarhandler *radar)
{
	u_int32_t result;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_BANGRADAR | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}

#if ATH_SUPPORT_ZERO_CAC_DFS
static int
radarSecondSegmentBangRadar(struct radarhandler *radar)
{
	u_int32_t result;
	struct ifreq ifr;

	radar->atd.ad_id = DFS_SECOND_SEGMENT_BANGRADAR | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
	radar->atd.ad_in_data = NULL;
	return 0;
}

static int
radarShowPreCACLists(struct radarhandler *radar)
{
	u_int32_t result;
	struct ifreq ifr;

	radar->atd.ad_id = DFS_SHOW_PRECAC_LISTS | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
	radar->atd.ad_in_data = NULL;
	return 0;
}

static int
radarResetPreCACLists(struct radarhandler *radar)
{
	u_int32_t result;
	struct ifreq ifr;

	radar->atd.ad_id = DFS_RESET_PRECAC_LISTS | ATH_DIAG_DYN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &result;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
	radar->atd.ad_in_data = NULL;
	return 0;
}
#endif
static void
radarGetThresholds(struct radarhandler *radar, struct dfs_ioctl_params *pe)
{
    struct ifreq ifr;
	radar->atd.ad_id = DFS_GET_THRESH | ATH_DIAG_DYN;
	radar->atd.ad_out_data = (void *) pe;
	radar->atd.ad_out_size = sizeof(struct dfs_ioctl_params);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
}

static int
radarGetUseNol(struct radarhandler *radar)
{
	u_int32_t result = 0;
    struct ifreq ifr;

	radar->atd.ad_id = DFS_GET_USENOL | ATH_DIAG_DYN;
	radar->atd.ad_in_data = NULL;
	radar->atd.ad_in_size = 0;
    radar->atd.ad_out_data = (void *) &result;
	radar->atd.ad_out_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t)&radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);

    /* clear references to local variables */
    radar->atd.ad_out_data = NULL;
	return(result);
}

static int
radarSetUsenol(struct radarhandler *radar, u_int32_t usenol )
{
    struct ifreq ifr;
    radar->atd.ad_id = DFS_SET_USENOL | ATH_DIAG_IN;
    radar->atd.ad_out_data = NULL;
    radar->atd.ad_out_size = 0;
    radar->atd.ad_in_data = (void *) &usenol;
    radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;
    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
              err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
        return 0;
}

static int
radarSetMuteTime(struct radarhandler *radar, u_int32_t dur)
{
    struct ifreq ifr;

	radar->atd.ad_id = DFS_MUTE_TIME | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &dur;
	radar->atd.ad_in_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;
	if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
	return 0;
}

static int
radarGetRadarDetects(struct radarhandler *radar)
{
    u_int32_t result= 0;
    struct ifreq ifr;

    radar->atd.ad_id = DFS_RADARDETECTS | ATH_DIAG_DYN;
    radar->atd.ad_in_data = NULL;
    radar->atd.ad_in_size = 0;
    radar->atd.ad_out_data = (void *) &result;
    radar->atd.ad_out_size = sizeof(u_int32_t);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;
    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
          err(1, radar->atd.ad_name);

    /* clear references to local variables */
    radar->atd.ad_out_data = NULL;
    return(result);
}

void
radarset(struct radarhandler *radar, int op, u_int32_t param)
{
	struct dfs_ioctl_params pe;
    struct ifreq ifr;

	pe.dfs_firpwr = DFS_IOCTL_PARAM_NOVAL;
	pe.dfs_rrssi = DFS_IOCTL_PARAM_NOVAL;
	pe.dfs_height = DFS_IOCTL_PARAM_NOVAL;
	pe.dfs_prssi = DFS_IOCTL_PARAM_NOVAL;
	pe.dfs_inband = DFS_IOCTL_PARAM_NOVAL;

	/* 5413 specific */
	pe.dfs_relpwr = DFS_IOCTL_PARAM_NOVAL;
	pe.dfs_relstep = DFS_IOCTL_PARAM_NOVAL;
	pe.dfs_maxlen = DFS_IOCTL_PARAM_NOVAL;

	switch(op) {
	case DFS_PARAM_FIRPWR:
		pe.dfs_firpwr = param;
		break;
	case DFS_PARAM_RRSSI:
		pe.dfs_rrssi = param;
		break;
	case DFS_PARAM_HEIGHT:
		pe.dfs_height = param;
		break;
	case DFS_PARAM_PRSSI:
		pe.dfs_prssi = param;
		break;
	case DFS_PARAM_INBAND:
		pe.dfs_inband = param;
		break;
	/* following are valid for 5413 only */
	case DFS_PARAM_RELPWR:
		pe.dfs_relpwr = param;
		break;
	case DFS_PARAM_RELSTEP:
		pe.dfs_relstep = param;
		break;
	case DFS_PARAM_MAXLEN:
		pe.dfs_maxlen = param;
		break;
	}
	radar->atd.ad_id = DFS_SET_THRESH | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &pe;
	radar->atd.ad_in_size = sizeof(struct dfs_ioctl_params);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;

    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
}

void
radarGetNol(struct radarhandler *radar, char *fname)
{
    struct ifreq ifr;
    struct dfsreq_nolinfo nolinfo;
    FILE *fp = NULL;
    char buf[100];
    int i;

    if (fname != NULL) {
        fp = fopen(fname, "wb");
        if (!fp) {
            memset(buf, '\0', sizeof(buf));
            snprintf(buf, sizeof(buf) - 1,"%s: fopen %s error",__func__, fname);
            perror(buf);
            return;
        }
    }

    radar->atd.ad_id = DFS_GET_NOL | ATH_DIAG_DYN;
    radar->atd.ad_in_data = NULL;
    radar->atd.ad_in_size = 0;
    radar->atd.ad_out_data = (void *) &nolinfo;
    radar->atd.ad_out_size = sizeof(struct dfsreq_nolinfo);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;

    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, radar->atd.ad_name);


    /*
     * Optionally dump the contents of dfsreq_nolinfo
     */
    if (fp != NULL) {
        fwrite(&nolinfo, sizeof(struct dfsreq_nolinfo), 1, fp);
        fclose(fp);
    }

    /* clear references to local variables */
    radar->atd.ad_out_data = NULL;
}

void
radarSetNol(struct radarhandler *radar, char *fname)
{
    struct ifreq ifr;
    struct dfsreq_nolinfo nolinfo;
    FILE *fp;
    char buf[100];
    int i;

    fp = fopen(fname, "rb");
    if (!fp)
    {
        memset(buf, '\0', sizeof(buf));
        snprintf(buf, sizeof(buf) - 1,"%s: fopen %s error",__func__, fname);
	perror(buf);
	return;
    }

    fread(&nolinfo, sizeof(struct dfsreq_nolinfo), 1, fp);
    fclose(fp);

    for (i=0; i<nolinfo.ic_nchans; i++)
    {
		/* Modify for static analysis, prevent overrun */
		if ( i < IEEE80211_CHAN_MAX ) {
			printf("nol:%d channel=%d startticks=%llu timeout=%d \n",
				i, nolinfo.dfs_nol[i].nol_freq,
				(unsigned long long)nolinfo.dfs_nol[i].nol_start_ticks,
				nolinfo.dfs_nol[i].nol_timeout_ms);
		}
    }

    radar->atd.ad_id = DFS_SET_NOL | ATH_DIAG_IN;
    radar->atd.ad_out_data = NULL;
    radar->atd.ad_out_size = 0;
    radar->atd.ad_in_data = (void *) &nolinfo;
    radar->atd.ad_in_size = sizeof(struct dfsreq_nolinfo);

	if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
	{
		printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
		exit(-1);
	}

	ifr.ifr_data = (caddr_t) &radar->atd;

    if (ioctl(radar->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, radar->atd.ad_name);
    radar->atd.ad_in_data = NULL;
}

static void
usage(void)
{
	const char *msg = "\
Usage: radartool (-i <interface>) [cmd]\n\
firpwr X            set firpwr (thresh to check radar sig is gone) to X (int32)\n\
rrssi X             set radar rssi (start det) to X dB (u_int32)\n\
height X            set threshold for pulse height to X dB (u_int32)\n\
prssi               set threshold to checkif pulse is gone to X dB (u_int32)\n\
inband X            set threshold to check if pulse is inband to X (0.5 dB) (u_int32)\n\
dfstime X           set dfs test time to X secs\n\
en_relpwr_check X   enable/disable radar relative power check (AR5413 only)\n\
relpwr X            set threshold to check the relative power of radar (AR5413 only)\n\
usefir128 X         en/dis using in-band pwr measurement over 128 cycles(AR5413 only)\n\
en_block_check X    en/dis to block OFDM weak sig as radar det(AR5413 only)\n\
en_max_rrssi X      en/dis to use max rssi instead of last rssi (AR5413 only)\n\
en_relstep X        en/dis to check pulse relative step (AR5413 only)\n\
relstep X           set threshold to check relative step for pulse det(AR5413 only)\n\
maxlen X            set max length of radar signal(in 0.8us step) (AR5413 only)\n\
numdetects          get number of radar detects\n\
getnol              get NOL channel information\n\
setnol              set NOL channel information\n\
dfsdebug            set the DFS debug mask\n";
	fprintf(stderr, "%s", msg);
}

int
main(int argc, char *argv[])
{
#define	streq(a,b)	(strcasecmp(a,b) == 0)
	struct radarhandler radar;
	HAL_REVS revs;
    struct ifreq ifr;
	memset(&radar, 0, sizeof(radar));
	radar.s = socket(AF_INET, SOCK_DGRAM, 0);
	if (radar.s < 0)
		err(1, "socket");
    if (argc > 1 && strcmp(argv[1], "-i") == 0) {
        if (argc < 2) {
            fprintf(stderr, "%s: missing interface name for -i\n",
                    argv[0]);
            exit(-1);
        }
		if(strlcpy(radar.atd.ad_name, argv[2], sizeof(radar.atd.ad_name )) >= sizeof(radar.atd.ad_name))
		{
			printf("%s..Arg too long %s\n",__func__,argv[2]);
			exit(-1);
		}
        argc -= 2, argv += 2;
    } else
		if(strlcpy(radar.atd.ad_name, ATH_DEFAULT, sizeof(radar.atd.ad_name)) >= sizeof(radar.atd.ad_name))
		{
			printf("%s..Arg too long %s\n",__func__,ATH_DEFAULT);
			exit(-1);
		}

#if 0
	radar.atd.ad_id = HAL_DIAG_REVS;
	radar.atd.ad_out_data = (void *) &revs;
	radar.atd.ad_out_size = sizeof(revs);
    strcpy(ifr.ifr_name, radar.atd.ad_name);
    ifr.ifr_data = (caddr_t) &radar.atd;
	if (ioctl(radar.s, SIOCGATHDIAG, &ifr) < 0)
		err(1, radar.atd.ad_name);

	switch (revs.ah_devid) {
	case AR5210_PROD:
	case AR5210_DEFAULT:
		printf("No radar detection yet for a 5210\n");
		exit(0);
	case AR5211_DEVID:
	case AR5311_DEVID:
	case AR5211_DEFAULT:
	case AR5211_FPGA11B:
		printf("No radar detecton yet for a 5211\n");
		exit(0);
	case AR5212_FPGA:
	case AR5212_DEVID:
	case AR5212_DEVID_IBM:
	case AR5212_DEFAULT:
	case AR5212_AR5312_REV2:
	case AR5212_AR5312_REV7:
		break;
	default:
		printf("No radar detection for device 0x%x\n", revs.ah_devid);
		exit(0);
	}
#endif
	/*
	 * For strtoul():
	 *
	 * A base of '0' means "interpret as either base 10 or
	 * base 16, depending upon the string prefix".
	 */
	if (argc >= 2) {
		if(streq(argv[1], "firpwr")) {
			radarset(&radar, DFS_PARAM_FIRPWR, (u_int32_t) atoi(argv[2]));
		} else if (streq(argv[1], "rrssi")) {
			radarset(&radar, DFS_PARAM_RRSSI, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "height")) {
			radarset(&radar, DFS_PARAM_HEIGHT, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "prssi")) {
			radarset(&radar, DFS_PARAM_PRSSI, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "inband")) {
			radarset(&radar, DFS_PARAM_INBAND, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "dfstime")) {
			radarSetMuteTime(&radar, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "usenol")) {
			radarSetUsenol(&radar, atoi(argv[2]));
		} else if (streq(argv[1], "dfsdebug")) {
			radarSetDebugLevel(&radar,
			    (u_int32_t) strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "ignorecac")) {
			radarIgnoreCAC(&radar,
			    (u_int32_t) strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "setnoltimeout")) {
			radarSetNOLTimeout(&radar,
			    (u_int32_t) strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "fft")) {
			radarEnableFFT(&radar);
		} else if (streq(argv[1], "nofft")) {
			radarDisableFFT(&radar);
		} else if (streq(argv[1], "bangradar")) {
			radarBangRadar(&radar);
#if ATH_SUPPORT_ZERO_CAC_DFS
		} else if (streq(argv[1], "secondSegmentBangradar")) {
			radarSecondSegmentBangRadar(&radar);
		} else if (streq(argv[1], "showPreCACLists")) {
			radarShowPreCACLists(&radar);
		} else if (streq(argv[1], "resetPreCACLists")) {
			radarResetPreCACLists(&radar);
#endif
		} else if (streq(argv[1], "shownol")) {
			radarShowNol(&radar);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
		} else if (streq(argv[1], "shownolhistory")) {
			radarShowNolHistory(&radar);
#endif
		} else if (streq(argv[1], "disable")) {
			radarDisableDetect(&radar);
		} else if (streq(argv[1], "enable")) {
			radarEnableDetect(&radar);
		} else if (streq(argv[1], "numdetects")) {
			printf("Radar: detected %d radars\n", radarGetRadarDetects(&radar));
		} else if (streq(argv[1], "getnol")){
			radarGetNol(&radar, argv[2]);
		} else if (streq(argv[1], "setnol")) {
			radarSetNol(&radar, argv[2]);
		} else if (streq(argv[1],"-h")) {
			usage();
		/* Following are valid for 5413 only */
		} else if (streq(argv[1], "relpwr")) {
			radarset(&radar, DFS_PARAM_RELPWR, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "relstep")) {
			radarset(&radar, DFS_PARAM_RELSTEP, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "maxlen")) {
			radarset(&radar, DFS_PARAM_MAXLEN, strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "false_rssi_thr")) {
			radarSetFalseRssiThres(&radar,
			    (u_int32_t) strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "rfsat_peak_mag")) {
			radarSetPeakMag(&radar,
			    (u_int32_t) strtoul(argv[2], NULL, 0));
		} else if (streq(argv[1], "getcacvalidtime")) {
			printf(" dfstime : %d\n", radarGetCacValidTime(&radar));
		} else if (streq(argv[1], "setcacvalidtime")) {
			radarSetCacValidTime(&radar,
			    (u_int32_t) strtoul(argv[2], NULL, 0));
		}
	} else if (argc == 1) {
		struct dfs_ioctl_params pe = {0};
		u_int32_t nol;
		nol = radarGetUseNol(&radar);

        /*
         **      channel switch announcement (CSA). The AP does
         **      the following on radar detect:
         **      nol = 0, use CSA, but new channel is same as old channel
         **      nol = 1, use CSA and switch to new channel (default)
         **      nol = 2, do not use CSA and stay on same channel
         **
         **/

        printf ("Radar;\nUse NOL: %s\n",(nol==1) ? "yes" : "no");
        if (nol >= 2)
            printf ("No Channel Switch announcemnet\n");


		radarGetThresholds(&radar, &pe);
		printf ("Firpwr (thresh to see if radar sig is gone):  %d\n",pe.dfs_firpwr);
		printf ("Radar Rssi (thresh to start radar det in dB): %u\n",pe.dfs_rrssi);
		printf ("Height (thresh for pulse height (dB):         %u\n",pe.dfs_height);
		printf ("Pulse rssi (thresh if pulse is gone in dB):   %u\n",pe.dfs_prssi);
		printf ("Inband (thresh if pulse is inband (in 0.5dB): %u\n",pe.dfs_inband);
		/* Following are valid for 5413 only */
                if (pe.dfs_relpwr & DFS_IOCTL_PARAM_ENABLE)
                        printf ("Relative power check, thresh in 0.5dB steps: %u\n", pe.dfs_relpwr & ~DFS_IOCTL_PARAM_ENABLE);
                else
                        printf ("Relative power check disabled\n");
                if (pe.dfs_relstep & DFS_IOCTL_PARAM_ENABLE)
                        printf ("Relative step thresh in 0.5dB steps: %u\n", pe.dfs_relstep & ~DFS_IOCTL_PARAM_ENABLE);
                else
                        printf ("Relative step for pulse detection disabled\n");                printf ("Max length of radar sig in 0.8us units: %u\n",pe.dfs_maxlen);
	} else {
		usage ();
	}
	close (radar.s);
	return 0;
}
