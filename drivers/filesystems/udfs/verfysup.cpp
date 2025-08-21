////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*

 Module Name: VerfySup.cpp

 Abstract:

    This module implements the UDF verification routines.

 Environment:

    Kernel mode only

*/

#include            "udffs.h"

// define the file specific bug-check id
#define         UDF_BUG_CHECK_ID    UDF_FILE_VERIFY_FS_CONTROL

BOOLEAN
UDFMarkDevForVerifyIfVcbMounted(
    IN PVCB Vcb
    )

/*++

Routine Description:

    This routine checks to see if the specified Vcb is currently mounted on
    the device or not.  If it is,  it sets the verify flag on the device, if
    not then the state is noted in the Vcb.

Arguments:

    Vcb - This is the volume to check.

Return Value:

    TRUE if the device has been marked for verify here,  FALSE otherwise.

--*/
{
    BOOLEAN Marked = FALSE;
    KIRQL SavedIrql;

    IoAcquireVpbSpinLock(&SavedIrql);

    if (Vcb->Vpb == Vcb->Vpb->RealDevice->Vpb) {

        SetFlag(Vcb->Vpb->RealDevice->Flags, DO_VERIFY_VOLUME);
        Marked = TRUE;
    }
    else {

        //  Flag this to avoid the VPB spinlock in future passes.

        SetFlag(Vcb->VcbState, VCB_STATE_VPB_NOT_ON_DEVICE);
    }

    IoReleaseVpbSpinLock( SavedIrql );

    return Marked;
}

/*
Routine Description:
    This routine checks that the current Vcb is valid and currently mounted
    on the device.  It will raise on an error condition.
    We check whether the volume needs verification and the current state
    of the Vcb.
Arguments:

    Vcb - This is the volume to verify.
*/

VOID
UDFVerifyVcb(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    IO_STATUS_BLOCK Iosb;
    ULONG MediaChangeCount = 0;
    BOOLEAN ForceVerify = FALSE;
    BOOLEAN DevMarkedForVerify;

    // Fail immediately if the volume is in the progress of being dismounted
    // or has been marked invalid.

    if ((Vcb->VcbCondition == VcbInvalid) ||
       ((Vcb->VcbCondition == VcbDismountInProgress) && 
       (IrpContext->MajorFunction != IRP_MJ_CREATE))) {

        if (FlagOn(Vcb->VcbState, VCB_STATE_DISMOUNT_IN_PROGRESS)) {

            UDFRaiseStatus(IrpContext, STATUS_VOLUME_DISMOUNTED);
        }

        UDFRaiseStatus(IrpContext, STATUS_FILE_INVALID);
    }

    //  Capture the real device verify state.
    
    DevMarkedForVerify = UDFRealDevNeedsVerify(Vcb->Vpb->RealDevice);

    if (FlagOn(Vcb->VcbState, VCB_STATE_REMOVABLE_MEDIA) && !DevMarkedForVerify) {

        //  If the media is removable and the verify volume flag in the
        //  device object is not set then we want to ping the device
        //  to see if it needs to be verified.

        if (Vcb->VcbCondition != VcbMountInProgress) {

            Status = UDFTSendIOCTL(
                                (Vcb->Vpb->RealDevice->DeviceType == FILE_DEVICE_CD_ROM ?
                                IOCTL_CDROM_CHECK_VERIFY : IOCTL_DISK_CHECK_VERIFY ),
                                Vcb,
                                NULL, 0,
                                &MediaChangeCount, sizeof(ULONG),
                                FALSE, &Iosb);

            if (Iosb.Information != sizeof(ULONG)) {
        
                //  Be safe about the count in case the driver didn't fill it in

                MediaChangeCount = 0;
            }

            // There are four cases when we want to do a verify.  These are the
            // first three.
            //
            // 1. We are mounted,  and the device has become empty
            // 2. The device has returned verify required (=> DO_VERIFY_VOL flag is
            //    set, but could be due to hardware condition)
            // 3. Media change count doesn't match the one in the Vcb
            
            if (((Vcb->VcbCondition == VcbMounted) &&
                 UDFIsRawDevice(Status)) 
                ||
                (Status == STATUS_VERIFY_REQUIRED)
                ||
                (NT_SUCCESS(Status) &&
                 (Vcb->MediaChangeCount != MediaChangeCount))) {

                //  If we are currently the volume on the device then it is our
                //  responsibility to set the verify flag.  If we're not on the device,
                //  then we shouldn't touch the flag.

                if (!FlagOn(Vcb->VcbState, VCB_STATE_VPB_NOT_ON_DEVICE)) {

                     DevMarkedForVerify = UDFMarkDevForVerifyIfVcbMounted(Vcb);
                }

                ForceVerify = TRUE;

                // NOTE that we no longer update the media change count here. We
                // do so only when we've actually completed a verify at a particular
                // change count value.
            }
        }

        // This is the 4th verify case.

        // We ALWAYS force CREATE requests on unmounted volumes through the 
        // verify path.  These requests could have been in limbo between
        // IoCheckMountedVpb and us when a verify/mount took place and caused
        // a completely different fs/volume to be mounted.  In this case the
        // checks above may not have caught the condition,  since we may already
        // have verified (wrong volume) and decided that we have nothing to do.
        // We want the requests to be re routed to the currently mounted volume,
        // since they were directed at the 'drive',  not our volume.

        if (NT_SUCCESS(Status) && !ForceVerify && !DevMarkedForVerify &&
            (IrpContext->MajorFunction == IRP_MJ_CREATE))  {

            PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( IrpContext->Irp);

            ForceVerify = (IrpSp->FileObject->RelatedFileObject == NULL) &&
                          ((Vcb->VcbCondition == VcbDismountInProgress) ||
                           (Vcb->VcbCondition == VcbNotMounted));

            //
            // Note that we don't touch the device verify flag here.  It required
            // it would have been caught and set by the first set of checks.
            //
        }
    }

    // Raise the verify / error if neccessary.
    
    if (ForceVerify || DevMarkedForVerify || !NT_SUCCESS( Status)) {
    
        IoSetHardErrorOrVerifyDevice( IrpContext->Irp,
                                      Vcb->Vpb->RealDevice );
       
        UDFRaiseStatus(IrpContext, ForceVerify ? STATUS_VERIFY_REQUIRED : Status);
    }

    // Based on the condition of the Vcb we'll either return to our
    // caller or raise an error condition

    switch (Vcb->VcbCondition) {

    case VcbNotMounted:

        IoSetHardErrorOrVerifyDevice(IrpContext->Irp, Vcb->Vpb->RealDevice);

        UDFRaiseStatus(IrpContext, STATUS_WRONG_VOLUME);
        break;

    case VcbInvalid:
    case VcbDismountInProgress:

        if (FlagOn(Vcb->VcbState, VCB_STATE_DISMOUNT_IN_PROGRESS)) {

            UDFRaiseStatus(IrpContext, STATUS_VOLUME_DISMOUNTED);

        } else {

            UDFRaiseStatus(IrpContext, STATUS_FILE_INVALID);
        }
        break;
    }
} // end UDFVerifyVcb()

/*

Routine Description:
    This routine performs the verify volume operation.  It is responsible for
    either completing of enqueuing the input Irp.

Arguments:
    Irp - Supplies the Irp to process

Return Value:

    NTSTATUS - The return status for the operation

--*/
NTSTATUS
UDFVerifyVolume(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
    PVPB Vpb = IrpSp->Parameters.VerifyVolume.Vpb;
    PVCB Vcb = (PVCB)IrpSp->Parameters.VerifyVolume.DeviceObject->DeviceExtension;
    PVCB NewVcb = NULL;
    IO_STATUS_BLOCK Iosb;
    ULONG MediaChangeCount = 0;
    NTSTATUS RC;
    ULONG Mode;
    BOOLEAN UnsafeIoctl = (Vcb->VcbState & UDF_VCB_FLAGS_UNSAFE_IOCTL) ? TRUE : FALSE;

    //  Update the real device in the IrpContext from the Vpb.  There was no available
    //  file object when the IrpContext was created.
    //    IrpContext->RealDevice = Vpb->RealDevice;
    UDFPrint(("UDFVerifyVolume:\n"));

    // Acquire the global resource to synchronise against mounts and teardown,
    // finally clause releases.

    UDFAcquireUdfData(IrpContext);

    UDFAcquireResourceExclusive(&(Vcb->VcbResource),TRUE);

    _SEH2_TRY {

        UDFPrint(("UDFVerifyVolume: Modified=%d\n", Vcb->Modified));
        // Check if the real device still needs to be verified.  If it doesn't
        // then obviously someone beat us here and already did the work
        // so complete the verify irp with success.  Otherwise reenable
        // the real device and get to work.
        if ( !(Vpb->RealDevice->Flags & DO_VERIFY_VOLUME) &&
            ((Vcb->VcbState & UDF_VCB_FLAGS_MEDIA_LOCKED) && !UnsafeIoctl) ) {
            UDFPrint(("UDFVerifyVolume: STATUS_SUCCESS (1)\n"));
            try_return(RC = STATUS_SUCCESS);
        }
        Vcb->VcbState &= ~UDF_VCB_FLAGS_UNSAFE_IOCTL;
        // Verify that there is a disk here.
        RC = UDFPhSendIOCTL( IOCTL_STORAGE_CHECK_VERIFY,
                                 Vcb->TargetDeviceObject,
                                 NULL,0,
                                 &MediaChangeCount,sizeof(ULONG),
                                 TRUE,&Iosb );

        if (!NT_SUCCESS( RC )) {
            // If we will allow a raw mount then return WRONG_VOLUME to
            // allow the volume to be mounted by raw.
            if (FlagOn( IrpSp->Flags, SL_ALLOW_RAW_MOUNT )) {
                UDFPrint(("UDFVerifyVolume: STATUS_WRONG_VOLUME (1)\n"));
                RC = STATUS_WRONG_VOLUME;
            }

            if (UDFIsRawDevice(RC)) {
                UDFPrint(("UDFVerifyVolume: STATUS_WRONG_VOLUME (2)\n"));
                RC = STATUS_WRONG_VOLUME;
            }
            try_return( RC );
        }

        if (Iosb.Information != sizeof(ULONG)) {
            // Be safe about the count in case the driver didn't fill it in
            MediaChangeCount = 0;
        }

        UDFPrint(("UDFVerifyVolume: Modified=%d\n", Vcb->Modified));
        UDFPrint(("UDFVerifyVolume: MediaChangeCount=%x, Vcb->MediaChangeCount=%x, UnsafeIoctl=%x\n",
            MediaChangeCount, Vcb->MediaChangeCount, UnsafeIoctl));
        // Verify that the device actually saw a change. If the driver does not
        // support the MCC, then we must verify the volume in any case.
        if (MediaChangeCount == 0 ||
            (Vcb->MediaChangeCount != MediaChangeCount) ||
           UnsafeIoctl ) {

            UDFPrint(("UDFVerifyVolume: compare\n"));

            NewVcb = (PVCB)MyAllocatePool__(NonPagedPool,sizeof(VCB));
            if (!NewVcb)
                try_return(RC=STATUS_INSUFFICIENT_RESOURCES);
            RtlZeroMemory(NewVcb,sizeof(VCB));

            NewVcb->TargetDeviceObject = Vcb->TargetDeviceObject;
            NewVcb->Vpb = Vpb;

            // Set the removable media flag based on the real device's
            // characteristics
            if (Vpb->RealDevice->Characteristics & FILE_REMOVABLE_MEDIA) {

                SetFlag(NewVcb->VcbState, VCB_STATE_REMOVABLE_MEDIA);
            }

            RC = UDFGetDiskInfo(IrpContext, NewVcb->TargetDeviceObject,NewVcb);
            if (!NT_SUCCESS(RC)) try_return(RC);
            // Prevent modification attempts durring Verify
            NewVcb->VcbState |= VCB_STATE_VOLUME_READ_ONLY |
                                VCB_STATE_MEDIA_WRITE_PROTECT;
            // Compare physical parameters (phase 1)
            UDFPrint(("UDFVerifyVolume: Modified=%d\n", Vcb->Modified));
            RC = UDFCompareVcb(IrpContext, Vcb, NewVcb, TRUE);
            if (!NT_SUCCESS(RC)) try_return(RC);

            // Initialize internal cache
            // in *** READ ONLY *** mode
            Mode = WCACHE_MODE_ROM;

            RC = WCacheInit__(&(NewVcb->FastCache),
                              UdfData.WCacheMaxFrames,
                              UdfData.WCacheMaxBlocks,
                              NewVcb->WriteBlockSize,
                              5, NewVcb->BlockSizeBits,
                              UdfData.WCacheBlocksPerFrameSh,
                              0/*NewVcb->FirstLBA*/, NewVcb->LastPossibleLBA, Mode,
                                  /*WCACHE_CACHE_WHOLE_PACKET*/ 0 |
                                  (Vcb->DoNotCompareBeforeWrite ? WCACHE_DO_NOT_COMPARE : 0) |
                                  WCACHE_MARK_BAD_BLOCKS | WCACHE_RO_BAD_BLOCKS, // speed up mount on bad disks
                              UdfData.WCacheFramesToKeepFree,
                              UDFTWrite, UDFTRead,
#ifdef UDF_ASYNC_IO
                          UDFTWriteAsync, UDFTReadAsync,
#else  //UDF_ASYNC_IO
                          NULL, NULL,
#endif //UDF_ASYNC_IO
                              UDFIsBlockAllocated, UDFUpdateVAT,
                              UDFWCacheErrorHandler);
            if (!NT_SUCCESS(RC)) try_return(RC);

            UDFPrint(("UDFVerifyVolume: Modified=%d\n", Vcb->Modified));
            RC = UDFGetDiskInfoAndVerify(IrpContext, NewVcb->TargetDeviceObject,NewVcb);
            UDFPrint(("  NewVcb->NSRDesc=%x\n", NewVcb->NSRDesc));
            if (!NT_SUCCESS(RC)) {
                if ((Vcb->VcbState & UDF_VCB_FLAGS_RAW_DISK) &&
                   (NewVcb->VcbState & UDF_VCB_FLAGS_RAW_DISK) &&
                   !(NewVcb->NSRDesc & VRS_ISO9660_FOUND)) {
                    UDFPrint(("UDFVerifyVolume: both are RAW -> remount\n", Vcb->Modified));
                    RC = STATUS_SUCCESS;
                    goto skip_logical_check;
                }
                if (RC == STATUS_UNRECOGNIZED_VOLUME) {
                    try_return(RC = STATUS_WRONG_VOLUME);
                }
                try_return(RC);
            }

            WCacheChFlags__(&(Vcb->FastCache),
                            WCACHE_CACHE_WHOLE_PACKET, // enable cache whole packet
                            WCACHE_MARK_BAD_BLOCKS | WCACHE_RO_BAD_BLOCKS);  // let user retry request on Bad Blocks

            NewVcb->VcbCondition = VcbMounted;
            // Compare logical parameters (phase 2)
            UDFPrint(("UDFVerifyVolume: Modified=%d\n", Vcb->Modified));
            RC = UDFCompareVcb(IrpContext, Vcb, NewVcb, FALSE);
            if (!NT_SUCCESS(RC)) try_return(RC);
            // We have unitialized WCache, so it is better to
            // force MOUNT_VOLUME call
            if (!WCacheIsInitialized__(&(Vcb->FastCache)))
                try_return(RC = STATUS_WRONG_VOLUME);

skip_logical_check:;

        }

        UDFPrint(("UDFVerifyVolume: compared\n"));
        UDFPrint(("UDFVerifyVolume: Modified=%d\n", Vcb->Modified));
        if (!(Vcb->VcbState & VCB_STATE_LOCKED)) {
            UDFPrint(("UDFVerifyVolume: set UDF_VCB_FLAGS_VOLUME_MOUNTED\n"));
            Vcb->VcbCondition = VcbMounted;
        }
        ClearFlag( Vpb->RealDevice->Flags, DO_VERIFY_VOLUME );

try_exit: NOTHING;

    } _SEH2_FINALLY {

        // Update the media change count to note that we have verified the volume
        // at this value
        Vcb->MediaChangeCount = MediaChangeCount;

        // If we got the wrong volume, mark the Vcb as not mounted.
        if (RC == STATUS_WRONG_VOLUME) {
            UDFPrint(("UDFVerifyVolume: clear UDF_VCB_FLAGS_VOLUME_MOUNTED\n"));
            Vcb->VcbCondition = VcbNotMounted;
            Vcb->WriteSecurity = FALSE;
        } else
        if (NT_SUCCESS(RC) &&
            Vcb->VcbCondition == VcbMounted) {
            BOOLEAN CacheInitialized = FALSE;
            UDFPrint(("    !!! VerifyVolume - QUICK REMOUNT !!!\n"));
            // Initialize internal cache
            CacheInitialized = WCacheIsInitialized__(&(Vcb->FastCache));
            if (!CacheInitialized) {
                Mode = WCACHE_MODE_ROM;
                RC = WCacheInit__(&(Vcb->FastCache),
                                  Vcb->WCacheMaxFrames,
                                  Vcb->WCacheMaxBlocks,
                                  Vcb->WriteBlockSize,
                                  5, Vcb->BlockSizeBits,
                              Vcb->WCacheBlocksPerFrameSh,
                              0/*Vcb->FirstLBA*/, Vcb->LastPossibleLBA, Mode,
                                  /*WCACHE_CACHE_WHOLE_PACKET*/ 0 |
                                  (Vcb->DoNotCompareBeforeWrite ? WCACHE_DO_NOT_COMPARE : 0) |
                                  (Vcb->CacheChainedIo ? WCACHE_CHAINED_IO : 0),
                              Vcb->WCacheFramesToKeepFree,
//                              UDFTWrite, UDFTRead,
                              UDFTWriteVerify, UDFTReadVerify,
#ifdef UDF_ASYNC_IO
                                  UDFTWriteAsync, UDFTReadAsync,
#else  //UDF_ASYNC_IO
                                  NULL, NULL,
#endif //UDF_ASYNC_IO
                                  UDFIsBlockAllocated, UDFUpdateVAT,
                                  UDFWCacheErrorHandler);
            }
            if (NT_SUCCESS(RC)) {
                if (!Vcb->VerifyCtx.VInited) {
                    RC = UDFVInit(Vcb);
                }
            }
            if (NT_SUCCESS(RC)) {

                if (!CacheInitialized) {
                    if (!(Vcb->VcbState & VCB_STATE_MEDIA_WRITE_PROTECT)) {
                        if (!Vcb->CDR_Mode) {
                            if (Vcb->TargetDeviceObject->DeviceType == FILE_DEVICE_DISK) {
                                UDFPrint(("UDFMountVolume: RAM mode\n"));
                                Mode = WCACHE_MODE_RAM;
                            } else {
                                UDFPrint(("UDFMountVolume: RW mode\n"));
                                Mode = WCACHE_MODE_RW;
                            }
        /*                    if (FsDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
                            } else {
                                Vcb->WriteSecurity = TRUE;
                            }*/
                        } else {
                            Mode = WCACHE_MODE_R;
                        }
                    }
                    WCacheSetMode__(&(Vcb->FastCache), Mode);

                    WCacheChFlags__(&(Vcb->FastCache),
                                    WCACHE_CACHE_WHOLE_PACKET, // enable cache whole packet
                                    WCACHE_MARK_BAD_BLOCKS | WCACHE_RO_BAD_BLOCKS);  // let user retry request on Bad Blocks
                }
                // we can't record ACL on old format disks
                if (!UDFNtAclSupported(Vcb)) {
                    Vcb->WriteSecurity = FALSE;
                    Vcb->UseExtendedFE = FALSE;
                }
            }
        }

        if (NewVcb) {
            // Release internal cache
            UDFPrint(("UDFVerifyVolume: delete NewVcb\n"));
            WCacheFlushAll__(IrpContext, &NewVcb->FastCache, NewVcb);
            WCacheRelease__(&NewVcb->FastCache);
            UDFCleanupVCB(NewVcb);
            MyFreePool__(NewVcb);
        }
        UDFReleaseResource(&(Vcb->VcbResource));
        UDFReleaseUdfData(IrpContext);
    } _SEH2_END;

    // Complete the request if no exception.

    UDFCompleteRequest(IrpContext, Irp, RC);

    UDFPrint(("UDFVerifyVolume: RC = %x\n", RC));

    return RC;
} // end UDFVerifyVolume ()

/*
Routine Description:

    This routines performs an IoVerifyVolume operation and takes the
    appropriate action.  If the verify is successful then we send the originating
    Irp off to an Ex Worker Thread.  This routine is called from the exception handler.
    No file system resources are held when this routine is called.

Arguments:

    Irp - The irp to send off after all is well and done.
    Device - The real device needing verification.

*/
NTSTATUS
UDFPerformVerify(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp,
    IN PDEVICE_OBJECT DeviceToVerify
    )
{

    PVCB Vcb;
    NTSTATUS RC = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpSp;

    UDFPrint(("UDFPerformVerify:\n"));
    if (!IrpContext) return STATUS_INVALID_PARAMETER;
    if (!Irp) return STATUS_INVALID_PARAMETER;

    //  Check if this Irp has a status of Verify required and if it does
    //  then call the I/O system to do a verify.
    //
    //  Skip the IoVerifyVolume if this is a mount or verify request
    //  itself.  Trying a recursive mount will cause a deadlock with
    //  the DeviceObject->DeviceLock.
    if ((IrpContext->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
       ((IrpContext->MinorFunction == IRP_MN_MOUNT_VOLUME) ||
        (IrpContext->MinorFunction == IRP_MN_VERIFY_VOLUME))) {

        return UDFPostRequest(IrpContext, Irp);
    }

    //  Extract a pointer to the Vcb from the VolumeDeviceObject.
    //  Note that since we have specifically excluded mount,
    //  requests, we know that IrpSp->DeviceObject is indeed a
    //  volume device object.

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    Vcb = (PVCB)IrpSp->DeviceObject->DeviceExtension;

    UDFPrint(("UDFPerformVerify: check\n"));
    //  Check if the volume still thinks it needs to be verified,
    //  if it doesn't then we can skip doing a verify because someone
    //  else beat us to it.
    _SEH2_TRY {

        if (DeviceToVerify->Flags & DO_VERIFY_VOLUME) {

            //  If the IopMount in IoVerifyVolume did something, and
            //  this is an absolute open, force a reparse.
            RC = IoVerifyVolume( DeviceToVerify, FALSE );

            // Bug?
/*            if (UDFIsRawDevice(RC)) {
                RC = STATUS_WRONG_VOLUME;
            }*/

            //  If the verify operation completed it will return
            //  either STATUS_SUCCESS or STATUS_WRONG_VOLUME, exactly.

            //  If UDFVerifyVolume encountered an error during
            //  processing, it will return that error.  If we got
            //  STATUS_WRONG_VOLUME from the verify, and our volume
            //  is now mounted, commute the status to STATUS_SUCCESS.
            if ((RC == STATUS_WRONG_VOLUME) &&
                (Vcb->VcbCondition == VcbMounted)) {
                RC = STATUS_SUCCESS;
            }

            //  Do a quick unprotected check here.  The routine will do
            //  a safe check.  After here we can release the resource.
            //  Note that if the volume really went away, we will be taking
            //  the Reparse path.

            //  If the device might need to go away then call our dismount routine.
            if (Vcb->VcbCondition == VcbDismountInProgress ||
                Vcb->VcbCondition == VcbInvalid ||
              ((Vcb->VcbCondition == VcbNotMounted) && (Vcb->VcbReference <= Vcb->VcbResidualReference))) {

                UDFPrint(("UDFPerformVerify: UDFCheckForDismount\n"));
                UDFAcquireUdfData(IrpContext);
                UDFCheckForDismount(IrpContext, Vcb, FALSE);
                UDFReleaseUdfData(IrpContext);
            }

            //  If this is a create and the verify succeeded then complete the
            //  request with a REPARSE status.
            if ((IrpContext->MajorFunction == IRP_MJ_CREATE) &&
                (IrpSp->FileObject->RelatedFileObject == NULL) &&
                ((RC == STATUS_SUCCESS) || (RC == STATUS_WRONG_VOLUME)) ) {

                UDFPrint(("UDFPerformVerify: IO_REMOUNT\n"));

                Irp->IoStatus.Information = IO_REMOUNT;

                Irp->IoStatus.Status = STATUS_REPARSE;
                IoCompleteRequest(Irp,IO_DISK_INCREMENT);

                UDFCleanupIrpContext(IrpContext);

                RC = STATUS_REPARSE;
                Irp = NULL;
                IrpContext = NULL;

            //  If there is still an error to process then call the Io system
            //  for a popup.
            } else if ((Irp != NULL) && !NT_SUCCESS( RC )) {

                UDFPrint(("UDFPerformVerify: check IoIsErrorUserInduced\n"));
                //  Fill in the device object if required.
                if (IoIsErrorUserInduced( RC ) ) {
                    IoSetHardErrorOrVerifyDevice( Irp, DeviceToVerify );
                }
                UDFPrint(("UDFPerformVerify: UDFNormalizeAndRaiseStatus\n"));
                UDFNormalizeAndRaiseStatus( IrpContext, RC );
            }
        }

        //  If there is still an Irp, send it off to an Ex Worker thread.
        if (IrpContext != NULL) {

            RC = UDFPostRequest( IrpContext, Irp );
        }

    } _SEH2_EXCEPT(UDFExceptionFilter( IrpContext, _SEH2_GetExceptionInformation())) {
        //  We had some trouble trying to perform the verify or raised
        //  an error ourselves.  So we'll abort the I/O request with
        //  the error status that we get back from the execption code.
        RC = UDFProcessException( IrpContext, Irp);
    } _SEH2_END;

    UDFPrint(("UDFPerformVerify: RC = %x\n", RC));

    return RC;

} // end UDFPerformVerify()

/*

Routine Description:

    This routine is called to check if a volume is ready for dismount.  This
    occurs when only file system references are left on the volume.

    If the dismount is not currently underway and the user reference count
    has gone to zero then we can begin the dismount.

    If the dismount is in progress and there are no references left on the
    volume (we check the Vpb for outstanding references as well to catch
    any create calls dispatched to the file system) then we can delete
    the Vcb.

Arguments:

    Vcb - Vcb for the volume to try to dismount.

*/
BOOLEAN
UDFCheckForDismount(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb,
    IN BOOLEAN Force
    )
{
    BOOLEAN UnlockVcb = TRUE;
    BOOLEAN VcbPresent = TRUE;
    KIRQL SavedIrql;

    ASSERT_IRP_CONTEXT(IrpContext);
    ASSERT_VCB(Vcb);

    ASSERT_EXCLUSIVE_CDDATA;

    // Acquire and lock this Vcb to check the dismount state.

    ASSERT(ExIsResourceAcquiredSharedLite(&Vcb->VcbResource) == FALSE);
    UDFAcquireVcbExclusive(IrpContext, Vcb, FALSE);

    // Lets get rid of any pending closes for this volume.

    UDFFspClose(Vcb);

    UDFLockVcb(IrpContext, Vcb);

    // If the dismount is not already underway then check if the
    // user reference count has gone to zero or we are being forced
    // to disconnect.  If so start the teardown on the Vcb.

    if (Vcb->VcbCondition != VcbDismountInProgress) {

        if (Vcb->VcbUserReference <= Vcb->VcbResidualUserReference || Force) {

            UDFUnlockVcb(IrpContext, Vcb);
            UnlockVcb = FALSE;
            VcbPresent = UDFDismountVcb(IrpContext, Vcb, Force == FALSE);
        }

    //  If the teardown is underway and there are absolutely no references
    //  remaining then delete the Vcb.  References here include the
    //  references in the Vcb and Vpb.

    } else if (Vcb->VcbReference == 0) {

        IoAcquireVpbSpinLock( &SavedIrql );

        //  If there are no file objects and no reference counts in the
        //  Vpb we can delete the Vcb.  Don't forget that we have the
        //  last reference in the Vpb.

        if (Vcb->Vpb->ReferenceCount == 1) {

            IoReleaseVpbSpinLock(SavedIrql);
            UDFUnlockVcb(IrpContext, Vcb);
            UnlockVcb = FALSE;
            UDFDeleteVCB(IrpContext, Vcb);
            VcbPresent = FALSE;

        } else {

            IoReleaseVpbSpinLock( SavedIrql );
        }
    }

    // Unlock the Vcb if still held.

    if (UnlockVcb) {

        UDFUnlockVcb(IrpContext, Vcb);
    }

    // Release any resources still acquired.

    if (VcbPresent) {

        UDFReleaseVcb(IrpContext, Vcb);
    }

    return VcbPresent;
} // end UDFCheckForDismount()


/*

Routine Description:

    This routine is called when all of the user references to a volume are
    gone.  We will initiate all of the teardown any system resources.

    If all of the references to this volume are gone at the end of this routine
    then we will complete the teardown of this Vcb and mark the current Vpb
    as not mounted.  Otherwise we will allocated a new Vpb for this device
    and keep the current Vpb attached to the Vcb.

Arguments:

    Vcb - Vcb for the volume to dismount.

Return Value:

    BOOLEAN - TRUE if we didn't delete the Vcb, FALSE otherwise.

*/
BOOLEAN
UDFDismountVcb(
    PIRP_CONTEXT IrpContext,
    IN PVCB Vcb,
    IN BOOLEAN FlushBeforeDismount
    )
{
    PVPB OldVpb;
    BOOLEAN VcbPresent = TRUE;
    KIRQL SavedIrql;

    BOOLEAN FinalReference;

    ASSERT_EXCLUSIVE_CDDATA;
    ASSERT_EXCLUSIVE_VCB(Vcb);

    //TODO:
    //UDFLockVcb(IrpContext, Vcb);

    //  We should only take this path once.
    ASSERT(Vcb->VcbCondition != VcbDismountInProgress);

    //  Mark the Vcb as DismountInProgress.
    Vcb->VcbCondition = VcbDismountInProgress;

    OldVpb = Vcb->Vpb;

    //  Remove the mount volume reference.
    UDFCloseResidual(IrpContext, Vcb);
    // the only residual reference is cleaned above

    //  Acquire the Vpb spinlock to check for Vpb references.
    IoAcquireVpbSpinLock(&SavedIrql);

    //  Remember if this is the last reference on this Vcb.  We incremented
    //  the count on the Vpb earlier so we get one last crack it.  If our
    //  reference has gone to zero but the vpb reference count is greater
    //  than zero then the Io system will be responsible for deleting the
    //  Vpb.
    FinalReference = (BOOLEAN)(OldVpb->ReferenceCount == 1);

    //  There is a reference count in the Vpb and in the Vcb.  We have
    //  incremented the reference count in the Vpb to make sure that
    //  we have last crack at it.  If this is a failed mount then we
    //  want to return the Vpb to the IO system to use for the next
    //  mount request.
    if (OldVpb->RealDevice->Vpb == OldVpb) {

        //  If not the final reference then swap out the Vpb.
        if (!FinalReference) {

            ASSERT(Vcb->SwapVpb != NULL);

            ASSERT( Vcb->SwapVpb != NULL );

            Vcb->SwapVpb->Type = IO_TYPE_VPB;
            Vcb->SwapVpb->Size = sizeof( VPB );
            Vcb->SwapVpb->RealDevice = OldVpb->RealDevice;

            Vcb->SwapVpb->RealDevice->Vpb = Vcb->SwapVpb;

            Vcb->SwapVpb->Flags = FlagOn(OldVpb->Flags, VPB_REMOVE_PENDING);

            IoReleaseVpbSpinLock(SavedIrql);

            // Indicate we used up the swap.
            Vcb->SwapVpb = NULL;

        //  We want to leave the Vpb for the IO system.  Mark it
        //  as being not mounted.  Go ahead and delete the Vcb as
        //  well.
        } else {

            //  Make sure to remove the last reference on the Vpb.

            OldVpb->ReferenceCount--;

            OldVpb->DeviceObject = NULL;
            ClearFlag(Vcb->Vpb->Flags, VPB_MOUNTED);
            ClearFlag(Vcb->Vpb->Flags, VPB_LOCKED | VPB_DIRECT_WRITES_ALLOWED);

            //  Clear the Vpb flag so we know not to delete it.
            Vcb->Vpb = NULL;

            IoReleaseVpbSpinLock(SavedIrql);
            UDFDeleteVCB(IrpContext, Vcb);
            VcbPresent = FALSE;
        }

    //  Someone has already swapped in a new Vpb.  If this is the final reference
    //  then the file system is responsible for deleting the Vpb.
    } else if (FinalReference) {

        //  Make sure to remove the last reference on the Vpb.
        OldVpb->ReferenceCount--;

        IoReleaseVpbSpinLock(SavedIrql);
        UDFDeleteVCB(IrpContext, Vcb);
        VcbPresent = FALSE;

    //  The current Vpb is no longer the Vpb for the device (the IO system
    //  has already allocated a new one).  We leave our reference in the
    //  Vpb and will be responsible for deleting it at a later time.
    } else {

        IoReleaseVpbSpinLock(SavedIrql);
    }

    //  Let our caller know whether the Vcb is still present.
    return VcbPresent;
} // end UDFDismountVcb()


NTSTATUS
UDFCompareVcb(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB OldVcb,
    IN PVCB NewVcb,
    IN BOOLEAN PhysicalOnly
    )
{
    NTSTATUS RC;
    UDF_FILE_INFO    RootFileInfo;
    BOOLEAN SimpleLogicalCheck = FALSE;

    UDFPrint(("UDFCompareVcb:\n"));
    if (UdfData.Flags & UDF_DATA_FLAGS_SHUTDOWN) {
        UDFPrint(("  WRONG_VOLUME\n"));
        return STATUS_WRONG_VOLUME;
    }

#define VCB_NE(x)   (OldVcb->x != NewVcb->x)

    // compare physical parameters
    if (PhysicalOnly) {
        UDFPrint(("  PhysicalOnly\n"));
        if (VCB_NE(FirstLBA) ||
           VCB_NE(LastLBA) ||
           VCB_NE(FirstTrackNum) ||
           VCB_NE(LastTrackNum) ||
           VCB_NE(NWA) ||
           VCB_NE(LastPossibleLBA) ||
           VCB_NE(PhSerialNumber) ||
           VCB_NE(PhErasable) ||
           VCB_NE(PhDiskType) ||
           VCB_NE(MediaClassEx) ||

          /* We cannot compare these flags, because NewVcb is in unconditional ReadOnly */

          /*((OldVcb->VcbState & UDF_VCB_FLAGS_VOLUME_READ_ONLY) != (NewVcb->VcbState & UDF_VCB_FLAGS_VOLUME_READ_ONLY)) ||
          ((OldVcb->VcbState & UDF_VCB_FLAGS_MEDIA_READ_ONLY)  != (NewVcb->VcbState & UDF_VCB_FLAGS_MEDIA_READ_ONLY)) ||*/

           VCB_NE(TargetDeviceObject) ||
    //       VCB_NE(xxx) ||
    //       VCB_NE(xxx) ||
           VCB_NE(LastSession) ) {

            UDFPrint(("  WRONG_VOLUME (2)\n"));
            return STATUS_WRONG_VOLUME;
        }
        // Note, MRWStatus can change while media is mounted (stoppped/in-progress/complete)
        // We can compare only (Vcb->MRWStatus == 0) values
        if ((OldVcb->MRWStatus == 0) != (NewVcb->MRWStatus == 0)) {
            UDFPrint(("  WRONG_VOLUME (4), missmatch MRW status\n"));
        }
        for(uint32 i=OldVcb->FirstTrackNum; i<=OldVcb->LastTrackNum; i++) {
            if (VCB_NE(TrackMap[i].FirstLba) ||
               VCB_NE(TrackMap[i].LastLba) ||
               VCB_NE(TrackMap[i].PacketSize) ||
               VCB_NE(TrackMap[i].TrackParam) ||
               VCB_NE(TrackMap[i].DataParam) ||
               VCB_NE(TrackMap[i].NWA_V) ) {
                UDFPrint(("  WRONG_VOLUME (3), missmatch trk %d\n", i));
                return STATUS_WRONG_VOLUME;
            }
        }
        UDFPrint(("  Vcb compare Ok\n"));
        return STATUS_SUCCESS;
    }

    // Something is nasty!!! We perform verify for not flushed volume
    // This should never happen, but some devices/buses and their drivers
    // can lead us to such condition. For example with help of RESET.
    // Now, we hope, that nobody changed media.
    // We shall make simplified logical structure check
    if (OldVcb->Modified) {
        UDFPrint(("  Vcb SIMPLE compare on !!!MODIFIED!!! volume\n"));
        ASSERT(FALSE);
        SimpleLogicalCheck = TRUE;
    }

    // compare logical structure
    if (!SimpleLogicalCheck && (OldVcb->InitVatCount != NewVcb->InitVatCount)) {
        UDFPrint(("  InitVatCount %d != %d \n", OldVcb->InitVatCount, NewVcb->InitVatCount));
        return STATUS_WRONG_VOLUME;
    }

    // Compare volume creation time
    if (OldVcb->VolCreationTime != NewVcb->VolCreationTime) {
        UDFPrint(("  VolCreationTime %I64x != %I64x \n", OldVcb->VolCreationTime, NewVcb->VolCreationTime));
        return STATUS_WRONG_VOLUME;
    }
    // Compare serial numbers
    if (OldVcb->SerialNumber != NewVcb->SerialNumber) {
        UDFPrint(("  SerialNumber %x != %x \n", OldVcb->SerialNumber, NewVcb->SerialNumber));
        return STATUS_WRONG_VOLUME;
    }
    // Compare volume idents
    if (!SimpleLogicalCheck &&
       RtlCompareUnicodeString(&(OldVcb->VolIdent),&(NewVcb->VolIdent),FALSE)) {
        UDFPrint(("  VolIdent missmatch \n"));
        return STATUS_WRONG_VOLUME;
    }
    if (SimpleLogicalCheck) {
        // do not touch RootDir. It can be partially recorded
        UDFPrint(("  SimpleLogicalCheck Ok\n"));
        return STATUS_SUCCESS;
    }

    RC = UDFOpenRootFile__(IrpContext, NewVcb, &NewVcb->RootLbAddr, &RootFileInfo);
    if (!NT_SUCCESS(RC)) {
        UDFPrint(("  Can't open root file, status %x\n", RC));
        UDFCleanUpFile__(NewVcb, &RootFileInfo);
        return STATUS_WRONG_VOLUME;
    }
    // perform exhaustive check
    if (!(OldVcb->RootIndexFcb)) {
        UDFPrint(("  !(OldVcb->RootDirFCB)\n"));
wr_vol:
        UDFCloseFile__(IrpContext, NewVcb, &RootFileInfo);
        UDFCleanUpFile__(NewVcb, &RootFileInfo);
        return STATUS_WRONG_VOLUME;
    }

    if (!UDFCompareFileInfo(&RootFileInfo, OldVcb->RootIndexFcb->FileInfo)) {
        UDFPrint(("  !UDFCompareFileInfo\n"));
        goto wr_vol;
    }
    UDFCloseFile__(IrpContext, NewVcb, &RootFileInfo);
    UDFCleanUpFile__(NewVcb, &RootFileInfo);

    UDFPrint(("UDFCompareVcb: Ok\n"));
    return STATUS_SUCCESS;

#undef VCB_NE

} // end UDFCompareVcb()

NTSTATUS
UDFVerifyFcbOperation (
    IN PIRP_CONTEXT IrpContext OPTIONAL,
    IN PFCB Fcb,
    IN PCCB Ccb
    )
{
    //TODO: impl
    return STATUS_SUCCESS;
}

BOOLEAN
CdMarkDevForVerifyIfVcbMounted (
    _Inout_ PVCB Vcb
    )

/*++

Routine Description:

    This routine checks to see if the specified Vcb is currently mounted on
    the device or not.  If it is,  it sets the verify flag on the device, if
    not then the state is noted in the Vcb.

Arguments:

    Vcb - This is the volume to check.

Return Value:

    TRUE if the device has been marked for verify here,  FALSE otherwise.

--*/

{
    BOOLEAN Marked = FALSE;
    KIRQL SavedIrql;

    IoAcquireVpbSpinLock( &SavedIrql );

#pragma prefast(suppress: 28175, "this is a filesystem driver, touching the vpb is allowed")
    if (Vcb->Vpb->RealDevice->Vpb == Vcb->Vpb)  {

        UDFMarkRealDevForVerify(Vcb->Vpb->RealDevice);
        Marked = TRUE;
    }
    else {

        //
        //  Flag this to avoid the VPB spinlock in future passes.
        //
        
        SetFlag(Vcb->VcbState, VCB_STATE_VPB_NOT_ON_DEVICE);
    }
    
    IoReleaseVpbSpinLock(SavedIrql);

    return Marked;
}

