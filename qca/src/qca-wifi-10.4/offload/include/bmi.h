/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


//==============================================================================
// BMI declarations and prototypes
//
// Author(s): ="Atheros"
//==============================================================================
#ifndef _BMI_H_
#define _BMI_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Header files */
#include "athdefs.h"
#include "a_types.h"
#include "a_osapi.h"
#include "bmi_msg.h"
#include "ol_if_athvar.h"
    

void
BMIInit(struct ol_ath_softc_net80211 *scn);

void
BMICleanup(struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIDone(struct hif_opaque_softc *device, struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIGetTargetInfo(struct hif_opaque_softc *device, struct bmi_target_info *targ_info, struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIReadMemory(struct hif_opaque_softc *device,
              A_UINT32 address,
              A_UCHAR *buffer,
              A_UINT32 length,
              struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIWriteMemory(struct hif_opaque_softc *device,
               A_UINT32 address,
               A_UCHAR *buffer,
               A_UINT32 length,
               struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIExecute(struct hif_opaque_softc *device,
           A_UINT32 address,
           A_UINT32 *param,
           struct ol_ath_softc_net80211 *scn,
           A_UINT32 wait);

A_STATUS
BMISetAppStart(struct hif_opaque_softc *device,
               A_UINT32 address,
               struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIReadSOCRegister(struct hif_opaque_softc *device,
                   A_UINT32 address,
                   A_UINT32 *param,
                   struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIWriteSOCRegister(struct hif_opaque_softc *device,
                    A_UINT32 address,
                    A_UINT32 param,
                    struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchInstall(struct hif_opaque_softc *device,
                   A_UINT32 ROM_addr,
                   A_UINT32 RAM_addr,
                   A_UINT32 nbytes,
                   A_UINT32 do_activate,
                   A_UINT32 *patch_id,
                   struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchUninstall(struct hif_opaque_softc *device,
                     A_UINT32 rompatch_id,
                     struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchActivate(struct hif_opaque_softc *device,
                    A_UINT32 rompatch_count,
                    A_UINT32 *rompatch_list,
                    struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchDeactivate(struct hif_opaque_softc *device,
                      A_UINT32 rompatch_count,
                      A_UINT32 *rompatch_list,
                      struct ol_ath_softc_net80211 *scn);

A_STATUS 
BMISignStreamStart(struct hif_opaque_softc *device,
                   A_UINT32 address,
                   A_UCHAR *buffer,
                   A_UINT32 length,
                   struct ol_ath_softc_net80211 *scn);

A_STATUS
BMILZStreamStart(struct hif_opaque_softc *device,
                 A_UINT32 address,
                 struct ol_ath_softc_net80211 *scn);

A_STATUS
BMILZData(struct hif_opaque_softc *device,
          A_UCHAR *buffer,
          A_UINT32 length,
          struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIFastDownload(struct hif_opaque_softc *device,
                A_UINT32 address,
                A_UCHAR *buffer,
                A_UINT32 length,
                struct ol_ath_softc_net80211 *scn);

A_STATUS
BMInvramProcess(struct hif_opaque_softc *device,
                A_UCHAR *seg_name,
                A_UINT32 *retval,
                struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIRawWrite(struct hif_opaque_softc *device,
            A_UCHAR *buffer,
            A_UINT32 length);

A_STATUS
BMIRawRead(struct hif_opaque_softc *device,
           A_UCHAR *buffer,
           A_UINT32 length,
           A_BOOL want_timeout);

#ifdef __cplusplus
}
#endif

#endif /* _BMI_H_ */
