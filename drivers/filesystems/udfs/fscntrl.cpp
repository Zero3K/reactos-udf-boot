////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*

 Module Name: FsCntrl.cpp

 Abstract:

    Contains code to handle the "File System IOCTL" dispatch entry point.

 Environment:

    Kernel mode only

*/

#include            "udffs.h"

// define the file specific bug-check id
#define         UDF_BUG_CHECK_ID    UDF_FILE_FS_CONTROL

PDIR_INDEX_HDR UDFDirIndexAlloc(IN uint_di i);

/*
 Function: UDFFSControl()

 Description:
    The I/O Manager will invoke this routine to handle a File System
    Control request (this is IRP_MJ_FILE_SYSTEM_CONTROL dispatch point)

*/
NTSTATUS
NTAPI
UDFFSControl(
    PDEVICE_OBJECT      DeviceObject,      // the logical volume device object
    PIRP                Irp                // I/O Request Packet
    )
{
    NTSTATUS            RC = STATUS_SUCCESS;
    PIRP_CONTEXT IrpContext = NULL;
    BOOLEAN             AreWeTopLevel = FALSE;

    UDFPrint(("\nUDFFSControl: \n\n"));

    FsRtlEnterFileSystem();
    ASSERT(DeviceObject);
    ASSERT(Irp);

    // set the top level context
    AreWeTopLevel = UDFIsIrpTopLevel(Irp);

    _SEH2_TRY {

        // get an IRP context structure and issue the request
        IrpContext = UDFCreateIrpContext(Irp, DeviceObject);
        if (IrpContext) {
            RC = UDFCommonFSControl(IrpContext, Irp);
        } else {

            UDFCompleteRequest(IrpContext, Irp, STATUS_INSUFFICIENT_RESOURCES);
            RC = STATUS_INSUFFICIENT_RESOURCES;
        }

    } _SEH2_EXCEPT(UDFExceptionFilter(IrpContext, _SEH2_GetExceptionInformation())) {

        UDFPrintErr(("UDFFSControl: exception ***"));
        RC = UDFProcessException(IrpContext, Irp);

        UDFLogEvent(UDF_ERROR_INTERNAL_ERROR, RC);
    } _SEH2_END;

    if (AreWeTopLevel) {
        IoSetTopLevelIrp(NULL);
    }

    FsRtlExitFileSystem();

    return(RC);
} // end UDFFSControl()

/*
 Function: UDFCommonFSControl()

 Description:
    The actual work is performed here.

 Expected Interrupt Level (for execution) :
  IRQL_PASSIVE_LEVEL (invocation at higher IRQL will cause execution
    to be deferred to a worker thread context)

 Return Value: STATUS_SUCCESS/Error
*/

NTSTATUS
UDFCommonFSControl(
    PIRP_CONTEXT IrpContext,
    PIRP Irp
    )
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    // We know this is a file system control so we'll case on the
    // minor function, and call a internal worker routine to complete
    // the irp.

    UDFPrint(("\nUDFCommonFSControl\n\n"));

    switch (IrpSp->MinorFunction)
    {
    case IRP_MN_USER_FS_REQUEST:
        UDFPrint(("  UDFFSControl: UserFsReq request ....\n"));

        Status = UDFUserFsCtrlRequest(IrpContext, Irp);
        break;
    case IRP_MN_MOUNT_VOLUME:

        UDFPrint(("  UDFFSControl: MOUNT_VOLUME request ....\n"));

        Status = UDFMountVolume(IrpContext, Irp);
        break;
    case IRP_MN_VERIFY_VOLUME:

        UDFPrint(("  UDFFSControl: VERIFY_VOLUME request ....\n"));

        Status = UDFVerifyVolume(IrpContext, Irp);
        break;
    default:

        UDFPrintErr(("  UDFFSControl: STATUS_INVALID_DEVICE_REQUEST MinorFunction %x\n", (IrpSp)->MinorFunction));
        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_DEVICE_REQUEST);
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return Status;
} // end UDFCommonFSControl()

/*
Routine Description:
    This is the common routine for implementing the user's requests made
    through NtFsControlFile.

Arguments:
    Irp - Supplies the Irp being processed

Return Value:
    NTSTATUS - The return status for the operation

*/
NTSTATUS
NTAPI
UDFUserFsCtrlRequest(
    PIRP_CONTEXT IrpContext,
    PIRP             Irp
    )
{
    NTSTATUS RC;
    PEXTENDED_IO_STACK_LOCATION IrpSp = (PEXTENDED_IO_STACK_LOCATION) IoGetCurrentIrpStackLocation( Irp );

    //  Case on the control code.
    switch ( IrpSp->Parameters.FileSystemControl.FsControlCode ) {

    case FSCTL_REQUEST_OPLOCK_LEVEL_1 :
    case FSCTL_REQUEST_OPLOCK_LEVEL_2 :
    case FSCTL_REQUEST_BATCH_OPLOCK :
    case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE :
    case FSCTL_OPBATCH_ACK_CLOSE_PENDING :
    case FSCTL_OPLOCK_BREAK_NOTIFY :
    case FSCTL_OPLOCK_BREAK_ACK_NO_2 :
    case FSCTL_REQUEST_FILTER_OPLOCK :

        UDFPrint(("UDFUserFsCtrlRequest: OPLOCKS\n"));

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_DEVICE_REQUEST);
        RC = STATUS_INVALID_DEVICE_REQUEST;
        break;
/*
        RC = UDFOplockRequest( IrpContext, Irp );
        break;
*/
    case FSCTL_INVALIDATE_VOLUMES :

        RC = UDFInvalidateVolumes( IrpContext, Irp );
        break;
/*
    case FSCTL_MOVE_FILE:

    case FSCTL_QUERY_ALLOCATED_RANGES:
    case FSCTL_SET_ZERO_DATA:
    case FSCTL_SET_SPARSE:

    case FSCTL_MARK_VOLUME_DIRTY:

        RC = UDFDirtyVolume( IrpContext, Irp );
        break;

  */
    case FSCTL_IS_VOLUME_DIRTY:

        RC = UDFIsVolumeDirty(IrpContext, Irp);
        break;

    case FSCTL_ALLOW_EXTENDED_DASD_IO:

        UDFPrint(("UDFUserFsCtrlRequest: FSCTL_ALLOW_EXTENDED_DASD_IO\n"));
        // DASD i/o is always permitted
        // So, no-op this call

        UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);
        RC = STATUS_SUCCESS;
        break;

    case FSCTL_DISMOUNT_VOLUME:

        RC = UDFDismountVolume( IrpContext, Irp );
        break;

    case FSCTL_IS_VOLUME_MOUNTED:

        RC = UDFIsVolumeMounted( IrpContext, Irp );
        break;

    case FSCTL_LOCK_VOLUME:

        RC = UDFLockVolume( IrpContext, Irp );
        break;

    case FSCTL_UNLOCK_VOLUME:

        RC = UDFUnlockVolume( IrpContext, Irp );
        break;

    case FSCTL_IS_PATHNAME_VALID:

        RC = UDFIsPathnameValid( IrpContext, Irp );
        break;

    case FSCTL_GET_VOLUME_BITMAP:

        UDFPrint(("UDFUserFsCtrlRequest: FSCTL_GET_VOLUME_BITMAP\n"));
        RC = UDFGetVolumeBitmap( IrpContext, Irp );
        break;

    case FSCTL_GET_RETRIEVAL_POINTERS:

        UDFPrint(("UDFUserFsCtrlRequest: FSCTL_GET_RETRIEVAL_POINTERS\n"));
        RC = UDFGetRetrievalPointers( IrpContext, Irp, 0 );
        break;


    //  We don't support any of the known or unknown requests.
    default:

        UDFPrintErr(("UDFUserFsCtrlRequest: STATUS_INVALID_DEVICE_REQUEST for %x\n",
            IrpSp->Parameters.FileSystemControl.FsControlCode));

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_DEVICE_REQUEST);
        RC = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return RC;

} // end UDFUserFsCtrlRequest()


/*
Routine Description:
    This is the common routine for implementing the mount requests

Arguments:
    Irp - Supplies the Irp being processed

Return Value:
    NTSTATUS - The return status for the operation

*/
NTSTATUS
NTAPI
UDFMountVolume(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    NTSTATUS                RC;
    PIO_STACK_LOCATION      IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT          TargetDeviceObject = NULL;
    PDEVICE_OBJECT          fsDeviceObject;
    PVPB                    Vpb = IrpSp->Parameters.MountVolume.Vpb;
    PVCB                    Vcb = NULL;
    PDEVICE_OBJECT          VolDo = NULL;
    IO_STATUS_BLOCK         Iosb;
    ULONG                   MediaChangeCount = 0;
    DEVICE_TYPE             FsDeviceType;
    BOOLEAN                 RestoreDoVerify = FALSE;
    BOOLEAN                 RemovableMedia = TRUE;
    BOOLEAN                 SetDoVerifyOnFail;
    ULONG                   Mode;
    BOOLEAN                 VcbAcquired = FALSE;
    BOOLEAN                 DeviceNotTouched = TRUE;
    DISK_GEOMETRY           DiskGeometry;

    ASSERT(IrpSp);
    UDFPrint(("\n !!! UDFMountVolume\n"));

    fsDeviceObject = IrpContext->RealDevice;
    UDFPrint(("Mount on device object %x\n", fsDeviceObject));

    // Get a pointer to the target physical/virtual device object.
    TargetDeviceObject = IrpSp->Parameters.MountVolume.DeviceObject;

    auto RealDevice = Vpb->RealDevice;
    
    SetDoVerifyOnFail = UDFRealDevNeedsVerify(RealDevice);

    if (FlagOn(TargetDeviceObject->Characteristics, FILE_FLOPPY_DISKETTE)) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_UNRECOGNIZED_VOLUME);
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    //  If we've shutdown disallow further mounts.

    if (FlagOn(UdfData.Flags, UDF_DATA_FLAGS_SHUTDOWN)) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_SYSTEM_SHUTDOWN);
        return STATUS_SYSTEM_SHUTDOWN;
    }

    RemovableMedia = FlagOn(TargetDeviceObject->Characteristics, FILE_REMOVABLE_MEDIA);

    if (TargetDeviceObject->DeviceType == FILE_DEVICE_CD_ROM) {
        FsDeviceType = FILE_DEVICE_CD_ROM_FILE_SYSTEM;
    } else {
        FsDeviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
    }

    //  Do a CheckVerify here to lift the MediaChange ticker from the driver
    RC = UDFPhSendIOCTL((RealDevice->DeviceType == FILE_DEVICE_CD_ROM ?
        IOCTL_CDROM_CHECK_VERIFY :
        IOCTL_DISK_CHECK_VERIFY),
        TargetDeviceObject,
        NULL, 0,
        &MediaChangeCount, sizeof(ULONG),
        TRUE,
        &Iosb);

    if (!NT_SUCCESS(RC)) {

        UDFCompleteRequest(IrpContext, Irp, RC);
        return RC;
    }

    RC = UDFPhSendIOCTL((RealDevice->DeviceType == FILE_DEVICE_CD_ROM ?
            IOCTL_CDROM_GET_DRIVE_GEOMETRY :
            IOCTL_DISK_GET_DRIVE_GEOMETRY),
            TargetDeviceObject,
            NULL, 0,
            &DiskGeometry, sizeof(DISK_GEOMETRY),
            TRUE,
            NULL);

    if (!NT_SUCCESS(RC)) {

        UDFCompleteRequest(IrpContext, Irp, RC);
        return RC;
    }

    // Acquire GlobalDataResource
    UDFAcquireResourceExclusive(&UdfData.GlobalDataResource, TRUE);

    _SEH2_TRY {

        UDFScanForDismountedVcb(IrpContext);

        if (!IS_ALIGNED_POWER_OF_2(DiskGeometry.BytesPerSector)) {

            try_return(RC = STATUS_DRIVER_INTERNAL_ERROR);
        }

        if (DiskGeometry.BytesPerSector > MAX_SECTOR_SIZE) {

            try_return(RC = STATUS_UNRECOGNIZED_VOLUME);
        }

        // Now before we can initialize the Vcb we need to set up the
        // Get our device object and alignment requirement.
        // Device extension == VCB
        UDFPrint(("UDFMountVolume: create device\n"));
        RC = IoCreateDevice( UdfData.DriverObject,
                                 sizeof(VCB),
                                 NULL,
                                 FsDeviceType,
                                 0,
                                 FALSE,
                                 &VolDo );

        if (!NT_SUCCESS(RC)) try_return(RC);

        // Our alignment requirement is the larger of the processor alignment requirement
        // already in the volume device object and that in the DeviceObjectWeTalkTo
        if (TargetDeviceObject->AlignmentRequirement > VolDo->AlignmentRequirement) {
            VolDo->AlignmentRequirement = TargetDeviceObject->AlignmentRequirement;
        }

        VolDo->Flags &= ~DO_DEVICE_INITIALIZING;

        // device object field in the VPB to point to our new volume device
        // object.
        Vpb->DeviceObject = (PDEVICE_OBJECT) VolDo;

        // We must initialize the stack size in our device object before
        // the following reads, because the I/O system has not done it yet.
        ((PDEVICE_OBJECT)VolDo)->StackSize = (CCHAR) (TargetDeviceObject->StackSize + 1);

        Vcb = (PVCB)VolDo->DeviceExtension;

        // Initialize the Vcb.  This routine will raise on an allocation
        // failure.
        RC = UDFInitializeVCB(IrpContext, VolDo, TargetDeviceObject, Vpb);
        if (!NT_SUCCESS(RC)) {
            Vcb = NULL;
            try_return(RC);
        }

        VolDo = NULL;
        Vpb = NULL;

        // Store the Vcb in the IrpContext as we didn't have one before.

        IrpContext->Vcb = Vcb;

        UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE );
        VcbAcquired = TRUE;

        // Let's reference the Vpb to make sure we are the one to
        // have the last dereference.
        Vcb->Vpb->ReferenceCount ++;

        Vcb->MediaChangeCount = MediaChangeCount;
        Vcb->FsDeviceType = FsDeviceType;

        // Clear the verify bit for the start of mount.
        UDFMarkRealDevVerifyOk(Vcb->Vpb->RealDevice);

        DeviceNotTouched = FALSE;
        RC = UDFGetDiskInfo(IrpContext, TargetDeviceObject, Vcb);
        if (!NT_SUCCESS(RC)) try_return(RC);

        //     ****  Read registry settings  ****
        UDFReadRegKeys(Vcb, FALSE, FALSE);

        Vcb->MountPhErrorCount = 0;

#ifdef UDF_USE_WCACHE
        // Initialize internal cache
        Mode = WCACHE_MODE_ROM;
        RC = WCacheInit__(&(Vcb->FastCache),
                          Vcb->WCacheMaxFrames,
                          Vcb->WCacheMaxBlocks,
                          Vcb->WriteBlockSize,
                          5, Vcb->BlockSizeBits,
                          Vcb->WCacheBlocksPerFrameSh,
                          0/*Vcb->FirstLBA*/, Vcb->LastPossibleLBA, Mode,
                              0/*WCACHE_CACHE_WHOLE_PACKET*/ |
                              (Vcb->DoNotCompareBeforeWrite ? WCACHE_DO_NOT_COMPARE : 0) |
                              (Vcb->CacheChainedIo ? WCACHE_CHAINED_IO : 0) |
                              WCACHE_MARK_BAD_BLOCKS | WCACHE_RO_BAD_BLOCKS,  // this will be cleared after mount
                          Vcb->WCacheFramesToKeepFree,
//                          UDFTWrite, UDFTRead,
                          UDFTWriteVerify, UDFTReadVerify,
#ifdef UDF_ASYNC_IO
                          UDFTWriteAsync, UDFTReadAsync,
#else  //UDF_ASYNC_IO
                          NULL, NULL,
#endif //UDF_ASYNC_IO
                          UDFIsBlockAllocated,
                          UDFUpdateVAT,
                          UDFWCacheErrorHandler);
        if (!NT_SUCCESS(RC)) try_return(RC);
#endif //UDF_USE_WCACHE

        RC = UDFVInit(Vcb);
        if (!NT_SUCCESS(RC)) try_return(RC);

        UDFAcquireResourceExclusive(&(Vcb->BitMapResource1),TRUE);
        RC = UDFGetDiskInfoAndVerify(IrpContext, TargetDeviceObject,Vcb);
        UDFReleaseResource(&(Vcb->BitMapResource1));

        ASSERT(!Vcb->Modified);
        WCacheChFlags__(&(Vcb->FastCache),
                        WCACHE_CACHE_WHOLE_PACKET, // enable cache whole packet
                        WCACHE_MARK_BAD_BLOCKS | WCACHE_RO_BAD_BLOCKS);  // let user retry request on Bad Blocks

        if (!NT_SUCCESS(RC)) {

            try_return(RC);

        } else {
            Vcb->MountPhErrorCount = -1;

            // set cache mode according to media type
            if (!(Vcb->VcbState & VCB_STATE_MEDIA_WRITE_PROTECT)) {
                UDFPrint(("UDFMountVolume: writable volume\n"));
                if (!Vcb->CDR_Mode) {
                    if (FsDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
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
                    UDFPrint(("UDFMountVolume: R mode\n"));
                    Mode = WCACHE_MODE_R;
                }
                // we can't record ACL on old format disks
                if (!UDFNtAclSupported(Vcb)) {
                    UDFPrint(("UDFMountVolume: NO ACL and ExtFE support\n"));
                    Vcb->WriteSecurity = FALSE;
                    Vcb->UseExtendedFE = FALSE;
                }
            }
#ifdef UDF_USE_WCACHE
            WCacheSetMode__(&(Vcb->FastCache), Mode);
#endif //UDF_USE_WCACHE

            // Complete mount operations: create root FCB
            UDFAcquireResourceExclusive(&(Vcb->BitMapResource1),TRUE);
            RC = UDFCompleteMount(IrpContext, Vcb);
            UDFReleaseResource(&(Vcb->BitMapResource1));
            if (!NT_SUCCESS(RC)) {
                // We must have Vcb->VcbReference = 1 for UDFBlankMount()
                // Thus, we should not decrement it here
                // Also, if we shall not perform BlankMount,
                // but simply cleanup and return error, Vcb->VcbReference
                // will be decremented during cleanup. Thus anyway it must
                // stay 1 unchanged here
                //UDFInterlockedDecrement((PLONG)&(Vcb->VcbReference));
                UDFCloseResidual(IrpContext, Vcb);
                Vcb->VcbReference = 1;

                try_return(RC);
            }
        }

        if ((Vcb->VcbState & VCB_STATE_MEDIA_WRITE_PROTECT)) {
            UDFPrint(("UDFMountVolume: RO mount\n"));
            Vcb->VcbState |= VCB_STATE_VOLUME_READ_ONLY;
        }

        Vcb->Vpb->SerialNumber = Vcb->PhSerialNumber;
        Vcb->Vpb->VolumeLabelLength = Vcb->VolIdent.Length;
        RtlCopyMemory( Vcb->Vpb->VolumeLabel,
                       Vcb->VolIdent.Buffer,
                       Vcb->VolIdent.Length );

        Vcb->VcbCondition = VcbMounted;

        UDFInterlockedDecrement((PLONG)&(Vcb->VcbReference));
        Vcb->TotalAllocUnits = UDFGetTotalSpace(Vcb);
        Vcb->FreeAllocUnits = UDFGetFreeSpace(Vcb);

        if (UdfData.MountEvent)
        {
            Vcb->IsVolumeJustMounted = TRUE;
            KeSetEvent(UdfData.MountEvent, 0, FALSE);
        }

        //  The new mount is complete.
        UDFReleaseResource( &(Vcb->VcbResource) );
        VcbAcquired = FALSE;
        Vcb = NULL;

        RC = STATUS_SUCCESS;

try_exit: NOTHING;
    } _SEH2_FINALLY {

        if (!NT_SUCCESS(RC)) {

            // If we didn't complete the mount then cleanup any remaining structures.
            if (Vpb) {
               Vpb->DeviceObject = NULL;
            }

            if (Vcb) {
                // Restore the verify bit.
                if (RestoreDoVerify) {
                    Vcb->Vpb->RealDevice->Flags |= DO_VERIFY_VOLUME;
                }
                // Make sure there is no Vcb since it could go away
                if (Vcb->VcbReference)
                    UDFInterlockedDecrement((PLONG)&(Vcb->VcbReference));
                // This procedure will also delete the volume device object
                if (UDFDismountVcb(IrpContext, Vcb, VcbAcquired )) {
                    UDFReleaseResource( &(Vcb->VcbResource) );
                }
            } else if (VolDo) {
                IoDeleteDevice( VolDo );
            }
        }

        //  If we are not mounting the device,  then set the verify bit again.

        if ((_SEH2_AbnormalTermination() || !NT_SUCCESS(RC)) && 
            SetDoVerifyOnFail) {

            UDFMarkRealDevForVerify(RealDevice);
        }

        // Release the global resource.
        UDFReleaseResource(&UdfData.GlobalDataResource);

    } _SEH2_END;

    //  Now send mount notification.
    if (NT_SUCCESS(RC)) {

        PFILE_OBJECT FileObject = IoCreateStreamFileObject(NULL, RealDevice);
        if (FileObject) {
            FsRtlNotifyVolumeEvent(FileObject, FSRTL_VOLUME_MOUNT);
            ObDereferenceObject(FileObject);
        }
    }

    // Complete the request if no exception.
    UDFCompleteRequest(IrpContext, Irp, RC);

    UDFPrint(("UDFMountVolume: final RC = %x\n", RC));
    return RC;

} // end UDFMountVolume()

VOID
UDFCloseResidual(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb
    )
{
    //  Deinitialize Non-alloc file
    if (Vcb->VcbReference)
        UDFInterlockedDecrement((PLONG)&(Vcb->VcbReference));
    UDFPrint(("UDFCloseResidual: NonAllocFileInfo %x\n", Vcb->NonAllocFileInfo));
    if (Vcb->NonAllocFileInfo) {
        UDFCloseFile__(IrpContext, Vcb, Vcb->NonAllocFileInfo);
        UDFCleanUpFile__(Vcb, Vcb->NonAllocFileInfo);
        MyFreePool__(Vcb->NonAllocFileInfo);
        Vcb->NonAllocFileInfo = NULL;
    }
    //  Deinitialize Unique ID Mapping
    UDFPrint(("UDFCloseResidual: NonAllocFileInfo %x\n", Vcb->NonAllocFileInfo));
    if (Vcb->UniqueIDMapFileInfo) {
        UDFCloseFile__(IrpContext, Vcb, Vcb->UniqueIDMapFileInfo);
        UDFCleanUpFile__(Vcb, Vcb->UniqueIDMapFileInfo);
        MyFreePool__(Vcb->UniqueIDMapFileInfo);
        Vcb->UniqueIDMapFileInfo = NULL;
    }
    //  Deinitialize VAT file
    UDFPrint(("UDFCloseResidual: VatFileInfo %x\n", Vcb->VatFileInfo));
    if (Vcb->VatFileInfo) {
        UDFCloseFile__(IrpContext, Vcb,Vcb->VatFileInfo);
        UDFCleanUpFile__(Vcb, Vcb->VatFileInfo);
        MyFreePool__(Vcb->VatFileInfo);
        Vcb->VatFileInfo = NULL;
    }
    //  System StreamDir
    UDFPrint(("UDFCloseResidual: SysSDirFileInfo %x\n", Vcb->SysSDirFileInfo));
    if (Vcb->SysSDirFileInfo) {
        UDFCloseFile__(IrpContext, Vcb, Vcb->SysSDirFileInfo);
        UDFCleanUpFile__(Vcb, Vcb->SysSDirFileInfo);
        MyFreePool__(Vcb->SysSDirFileInfo);
        Vcb->SysSDirFileInfo = NULL;
    }
/*    //  Deinitialize root dir fcb
    if (Vcb->RootDirFCB) {
        UDFCloseFile__(Vcb,Vcb->RootDirFCB->FileInfo);
        UDFCleanUpFile__(Vcb, Vcb->RootDirFCB->FileInfo);
        MyFreePool__(Vcb->RootDirFCB->FileInfo);
        UDFCleanUpFCB(Vcb->RootDirFCB);
        //  Remove root FCB reference in vcb
        if (Vcb->VcbReference) Vcb->VcbReference--;
    }

    // Deinitialize Non-alloc file
    if (Vcb->VcbReference) Vcb->VcbReference--;
    if (Vcb->NonAllocFileInfo) {
        UDFCloseFile__(Vcb,Vcb->NonAllocFileInfo);
        // We must release VCB here !!!!
//        UDFCleanUpFcbChain(Vcb, Vcb->NonAllocFileInfo, 1);
        Vcb->NonAllocFileInfo = NULL;
    }
    // Deinitialize VAT file
    if (Vcb->VatFileInfo) {
        UDFCloseFile__(Vcb,Vcb->VatFileInfo);
        // We must release VCB here !!!!
//        UDFCleanUpFcbChain(Vcb, Vcb->VatFileInfo, 1);
        Vcb->VatFileInfo = NULL;
    }*/

    // Deinitialize root dir fcb
    UDFPrint(("UDFCloseResidual: RootDirFCB %x\n", Vcb->RootIndexFcb));
    if (Vcb->RootIndexFcb) {
        UDFCloseFile__(IrpContext, Vcb, Vcb->RootIndexFcb->FileInfo);
        if (Vcb->RootIndexFcb->FcbCleanup)
            Vcb->RootIndexFcb->FcbCleanup--;
        UDFTeardownStructures(IrpContext, Vcb->RootIndexFcb, NULL);
        // Remove root FCB reference in vcb
        if (Vcb->VcbReference)
            UDFInterlockedDecrement((PLONG)&(Vcb->VcbReference));
        Vcb->RootIndexFcb = NULL;
    }
} // end UDFCloseResidual()

VOID
UDFCleanupVCB(
    IN PVCB Vcb
    )
{
    _SEH2_TRY {
        UDFReleaseFileIdCache(Vcb);
        UDFReleaseDlocList(Vcb);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        BrutePoint();
    } _SEH2_END;

    MyFreeMemoryAndPointer(Vcb->Partitions);
    MyFreeMemoryAndPointer(Vcb->LVid);
    MyFreeMemoryAndPointer(Vcb->Vat);
    MyFreeMemoryAndPointer(Vcb->SparingTable);

    if (Vcb->FSBM_Bitmap) {
        DbgFreePool(Vcb->FSBM_Bitmap);
        Vcb->FSBM_Bitmap = NULL;
    }
    if (Vcb->ZSBM_Bitmap) {
        DbgFreePool(Vcb->ZSBM_Bitmap);
        Vcb->ZSBM_Bitmap = NULL;
    }
    if (Vcb->BSBM_Bitmap) {
        DbgFreePool(Vcb->BSBM_Bitmap);
        Vcb->BSBM_Bitmap = NULL;
    }
#ifdef UDF_TRACK_ONDISK_ALLOCATION_OWNERS
    if (Vcb->FSBM_Bitmap_owners) {
        DbgFreePool(Vcb->FSBM_Bitmap_owners);
        Vcb->FSBM_Bitmap_owners = NULL;
    }
#endif //UDF_TRACK_ONDISK_ALLOCATION_OWNERS
    if (Vcb->FSBM_OldBitmap) {
        DbgFreePool(Vcb->FSBM_OldBitmap);
        Vcb->FSBM_OldBitmap = NULL;
    }

    MyFreeMemoryAndPointer(Vcb->VolIdent.Buffer);

    if (Vcb->ZBuffer) {
        DbgFreePool(Vcb->ZBuffer);
        Vcb->ZBuffer = NULL;
    }

    if (Vcb->fZBuffer) {
        DbgFreePool(Vcb->fZBuffer);
        Vcb->fZBuffer = NULL;
    }

    MyFreeMemoryAndPointer(Vcb->TrackMap);

} // end UDFCleanupVCB()

/*

Routine Description:

    This routine walks through the list of Vcb's looking for any which may
    now be deleted.  They may have been left on the list because there were
    outstanding references.

Arguments:

Return Value:

    None

*/
VOID
UDFScanForDismountedVcb(
    IN PIRP_CONTEXT IrpContext
    )
{
    PVCB Vcb;
    PLIST_ENTRY Link;


    // Walk through all of the Vcb's attached to the global data.
    Link = UdfData.VcbQueue.Flink;

    while (Link != &(UdfData.VcbQueue)) {

        Vcb = CONTAINING_RECORD( Link, VCB, NextVCB );

        // Move to the next link now since the current Vcb may be deleted.
        Link = Link->Flink;

        // If dismount is already underway then check if this Vcb can
        // go away.
        if ((Vcb->VcbCondition == VcbDismountInProgress) ||
            (Vcb->VcbCondition == VcbInvalid) ||
            ((Vcb->VcbCondition == VcbNotMounted) && (Vcb->VcbReference <= UDF_RESIDUAL_REFERENCE))) {

            UDFCheckForDismount(IrpContext, Vcb, FALSE);
        }
    }

    return;
} // end UDFScanForDismountedVcb()

/*
Routine Description:
    This routine determines if a volume is currently mounted.

Arguments:
    Irp - Supplies the Irp to process

Return Value:
    NTSTATUS - The return status for the operation

*/
NTSTATUS
UDFIsVolumeMounted(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
    PFCB Fcb;
    PCCB Ccb;

    UDFPrint(("UDFIsVolumeMounted\n"));

    // Decode the file object.

    UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    ASSERT_CCB(Ccb);
    ASSERT_FCB(Fcb);

    if (!Ccb) {

        UDFPrintErr(("  !Ccb\n"));

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);

        return STATUS_INVALID_PARAMETER;
    }

    if (Fcb &&
       !(Fcb->Vcb->VcbState & VCB_STATE_LOCKED) ) {

        // Disable PopUps, we want to return any error.
        IrpContext->Flags |= IRP_CONTEXT_FLAG_DISABLE_POPUPS;

        // Verify the Vcb.  This will raise in the error condition.
        UDFVerifyVcb( IrpContext, Fcb->Vcb );
    }

    UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);

    return STATUS_SUCCESS;
} // end UDFIsVolumeMounted()

/*
    This routine determines if pathname is valid path for UDF Filesystem
    We always succeed this request.

Arguments:
    Irp - Supplies the Irp to process

Return Value:
    NTSTATUS - The return status for the operation
*/
NTSTATUS
UDFIsPathnameValid(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    PAGED_CODE();

    UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;
} // end UDFIsPathnameValid()

/*
    This routine performs the actual unlock volume operation.
    The volume must be held exclusive by the caller.

Arguments:
    Vcb - The volume being locked.
    FileObject - File corresponding to the handle locking the volume.  If this
        is not specified, a system lock is assumed.

Return Value:
    NTSTATUS - The return status for the operation
    Attempting to remove a system lock that did not exist is OK.
*/
NTSTATUS
UDFUnlockVolumeInternal (
    IN PVCB Vcb,
    IN PFILE_OBJECT FileObject OPTIONAL
    )
{
    KIRQL SavedIrql;
    NTSTATUS Status = STATUS_NOT_LOCKED;

    IoAcquireVpbSpinLock(&SavedIrql);

    if (FlagOn(Vcb->Vpb->Flags, VPB_LOCKED) && FileObject == Vcb->VolumeLockFileObject) {

        // This one locked it, unlock the volume
        ClearFlag(Vcb->Vpb->Flags, VPB_LOCKED | VPB_DIRECT_WRITES_ALLOWED);
        ClearFlag(Vcb->VcbState, VCB_STATE_LOCKED);
        Vcb->VolumeLockFileObject = NULL;

        Status = STATUS_SUCCESS;
    }

    IoReleaseVpbSpinLock(SavedIrql);

    return Status;
} // end UDFUnlockVolumeInternal()

/*
    This routine performs the lock volume operation.  It is responsible for
    either completing of enqueuing the input Irp.
Arguments:
    Irp - Supplies the Irp to process
Return Value:
    NTSTATUS - The return status for the operation
*/
NTSTATUS
UDFLockVolume(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP             Irp
    )
{
    NTSTATUS RC;
    PVCB Vcb;
    PFCB Fcb;
    PCCB Ccb;

    KIRQL SavedIrql;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );

    BOOLEAN VcbAcquired = FALSE;

    // Decode the file object, the only type of opens we accept are
    // user volume opens.

    TYPE_OF_OPEN TypeOfOpen = UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    ASSERT_CCB(Ccb);
    
    // For UserVolumeOpen, Fcb is NULL (following FastFAT approach)
    if (TypeOfOpen != UserVolumeOpen) {
        ASSERT_FCB(Fcb);
    }

    if (!Ccb) {

        UDFPrintErr(("  !Ccb\n"));

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    // For UserVolumeOpen, get VCB from FileObject; for others, get from FCB
    if (TypeOfOpen == UserVolumeOpen) {
        Vcb = UDFGetVcbFromFileObject(IrpSp->FileObject);
    } else {
        Vcb = Fcb->Vcb;
    }
    ASSERT_VCB(Vcb);

    // Check for volume open (should be UserVolumeOpen with volume flags)
    if (TypeOfOpen != UserVolumeOpen || !(Ccb->Flags & UDF_CCB_VOLUME_OPEN)) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    FsRtlNotifyVolumeEvent(IrpSp->FileObject, FSRTL_VOLUME_LOCK);

    _SEH2_TRY {

        UDFCloseAllSystemDelayedInDir(Vcb, Vcb->RootIndexFcb->FileInfo);

#ifdef UDF_DELAYED_CLOSE
        UDFFspClose(Vcb);
#endif //UDF_DELAYED_CLOSE

        //  Acquire exclusive access to the Vcb.
        UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE );
        VcbAcquired = TRUE;

        //  Verify the Vcb.
        UDFVerifyVcb( IrpContext, Vcb );

        //  If the volume is already locked then complete with success if this file
        //  object has the volume locked, fail otherwise.
/*        if (Vcb->VcbState & UDF_VCB_FLAGS_VOLUME_LOCKED) {

            if (Vcb->VolumeLockFileObject == IrpSp->FileObject) {
                RC = STATUS_SUCCESS;
            } else {
                RC = STATUS_ACCESS_DENIED;
            }
        //  If the open count for the volume is greater than 1 then this request
        //  will fail.
        } else if (Vcb->VcbReference > UDF_RESIDUAL_REFERENCE+1) {
            RC = STATUS_ACCESS_DENIED;
        //  We will try to get rid of all of the user references.  If there is only one
        //  remaining after the purge then we can allow the volume to be locked.
        } else {
            // flush system cache
            UDFReleaseResource( &(Vcb->VcbResource) );
            VcbAcquired = FALSE;
        }*/

    } _SEH2_FINALLY {

        //  Release the Vcb.
        if (VcbAcquired) {
            UDFReleaseResource( &(Vcb->VcbResource) );
            VcbAcquired = FALSE;
        }
    } _SEH2_END;

    UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE );
    VcbAcquired = TRUE;
    UDFFlushVolume(IrpContext, Vcb);
    UDFReleaseResource( &(Vcb->VcbResource) );
    VcbAcquired = FALSE;
    //  Check if the Vcb is already locked, or if the open file count
    //  is greater than 1 (which implies that someone else also is
    //  currently using the volume, or a file on the volume).
    IoAcquireVpbSpinLock( &SavedIrql );

    if (!(Vcb->Vpb->Flags & VPB_LOCKED) &&
        (Vcb->VcbReference <= UDF_RESIDUAL_REFERENCE+1) &&
        (Vcb->Vpb->ReferenceCount == 2)) {

        // Mark volume as locked
        Vcb->Vpb->Flags |= VPB_LOCKED;
        Vcb->VcbState |= VCB_STATE_LOCKED;
        Vcb->VolumeLockFileObject = IrpSp->FileObject;

        RC = STATUS_SUCCESS;

    } else {

        RC = STATUS_ACCESS_DENIED;
    }

    IoReleaseVpbSpinLock( SavedIrql );

    if (!NT_SUCCESS(RC)) {
        FsRtlNotifyVolumeEvent(IrpSp->FileObject, FSRTL_VOLUME_LOCK_FAILED);
    }

    //  Complete the request if there haven't been any exceptions.

    UDFCompleteRequest(IrpContext, Irp, RC);
    return RC;
} // end UDFLockVolume()

_Requires_lock_held_(_Global_critical_region_)
_Requires_lock_held_(Vcb->VcbResource)
NTSTATUS
UDFLockVolumeInternal (
    _In_ PIRP_CONTEXT IrpContext,
    _Inout_ PVCB Vcb,
    _In_opt_ PFILE_OBJECT FileObject
    )

/*++

Routine Description:

    This routine performs the actual lock volume operation.  It will be called
    by anyone wishing to try to protect the volume for a long duration.  PNP
    operations are such a user.
    
    The volume must be held exclusive by the caller.

Arguments:

    Vcb - The volume being locked.
    
    FileObject - File corresponding to the handle locking the volume.  If this
        is not specified, a system lock is assumed.

Return Value:

    NTSTATUS - The return status for the operation

--*/

{
    NTSTATUS Status;
    KIRQL SavedIrql;
    NTSTATUS FinalStatus = (FileObject? STATUS_ACCESS_DENIED: STATUS_DEVICE_BUSY);
    //ULONG RemainingUserReferences = (FileObject? 1: 0);

    ASSERT_EXCLUSIVE_VCB(Vcb);

    //
    //  The cleanup count for the volume only reflects the fileobject that
    //  will lock the volume.  Otherwise, we must fail the request.
    //
    //  Since the only cleanup is for the provided fileobject, we will try
    //  to get rid of all of the other user references.  If there is only one
    //  remaining after the purge then we can allow the volume to be locked.
    //

    UDFFlushVolume(IrpContext, Vcb);
    //CdPurgeVolume( IrpContext, Vcb, FALSE );

    //
    //  Now back out of our synchronization and wait for the lazy writer
    //  to finish off any lazy closes that could have been outstanding.
    //
    //  Since we purged, we know that the lazy writer will issue all
    //  possible lazy closes in the next tick - if we hadn't, an otherwise
    //  unopened file with a large amount of dirty data could have hung
    //  around for a while as the data trickled out to the disk.
    //
    //  This is even more important now since we send notification to
    //  alert other folks that this style of check is about to happen so
    //  that they can close their handles.  We don't want to enter a fast
    //  race with the lazy writer tearing down his references to the file.
    //

    UDFReleaseResource(&Vcb->VcbResource);

    Status = CcWaitForCurrentLazyWriterActivity();

    //
    //  This is intentional. If we were able to get the Vcb before, just
    //  wait for it and take advantage of knowing that it is OK to leave
    //  the flag up.
    //

    SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
    UDFAcquireResourceExclusive(&Vcb->VcbResource, TRUE);
    
    if (!NT_SUCCESS( Status )) {

        return Status;
    }

    UDFCloseAllSystemDelayedInDir(Vcb, Vcb->RootIndexFcb->FileInfo);

#ifdef UDF_DELAYED_CLOSE
        UDFFspClose(Vcb);
#endif //UDF_DELAYED_CLOSE
    //FspClose( Vcb );

    //
    //  If the volume is already explicitly locked then fail.  We use the
    //  Vpb locked flag as an 'explicit lock' flag in the same way as Fat.
    //

    IoAcquireVpbSpinLock( &SavedIrql ); 

    // TODO: use VcbCleanup
    //if (!FlagOn( Vcb->Vpb->Flags, VPB_LOCKED ) && 
    //    (Vcb->VcbCleanup == RemainingUserReferences) &&
    //   (Vcb->VcbUserReference == CDFS_RESIDUAL_USER_REFERENCE + RemainingUserReferences))  {

    if (!(Vcb->Vpb->Flags & VPB_LOCKED) &&
        (Vcb->VcbReference <= UDF_RESIDUAL_REFERENCE+1) &&
        (Vcb->Vpb->ReferenceCount == 2)) {

        SetFlag(Vcb->VcbState, VCB_STATE_LOCKED);
        SetFlag(Vcb->Vpb->Flags, VPB_LOCKED);
        Vcb->VolumeLockFileObject = FileObject;
        FinalStatus = STATUS_SUCCESS;
    }
    
    IoReleaseVpbSpinLock( SavedIrql );  
    
    return FinalStatus;
}

/*
    This routine performs the unlock volume operation.  It is responsible for
    either completing of enqueuing the input Irp.
Arguments:
    Irp - Supplies the Irp to process
Return Value:
    NTSTATUS - The return status for the operation
*/
NTSTATUS
UDFUnlockVolume(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PVCB Vcb;
    PFCB Fcb;
    PCCB Ccb;

    // Decode the file object, the only type of opens we accept are
    // user volume opens.

    TYPE_OF_OPEN TypeOfOpen = UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    ASSERT_CCB(Ccb);
    
    // For UserVolumeOpen, Fcb is NULL (following FastFAT approach)
    if (TypeOfOpen != UserVolumeOpen) {
        ASSERT_FCB(Fcb);
    }

    if (!Ccb) {
        UDFPrintErr(("  !Ccb\n"));

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    // For UserVolumeOpen, get VCB from FileObject; for others, get from FCB
    if (TypeOfOpen == UserVolumeOpen) {
        Vcb = UDFGetVcbFromFileObject(IrpSp->FileObject);
    } else {
        Vcb = Fcb->Vcb;
    }
    ASSERT_VCB(Vcb);

    // Check for volume open
    if (TypeOfOpen != UserVolumeOpen || !(Ccb->Flags & UDF_CCB_VOLUME_OPEN)) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    // Acquire the volume resource exclusive
    UDFAcquireResourceExclusive(&Vcb->VcbResource, TRUE);

    // We won't check for a valid Vcb for this request.  An unlock will always
    // succeed on a locked volume.
    Status = UDFUnlockVolumeInternal(Vcb, IrpSp->FileObject);

    // Release all of our resources
    UDFReleaseResource(&Vcb->VcbResource);

    // Send notification that the volume is avaliable.
    if (NT_SUCCESS(Status)) {

        FsRtlNotifyVolumeEvent(IrpSp->FileObject, FSRTL_VOLUME_UNLOCK);
    }

    //  Complete the request if there haven't been any exceptions.

    UDFCompleteRequest(IrpContext, Irp, Status);

    return Status;
} // end UDFUnlockVolume()


/*
    This routine performs the dismount volume operation.  It is responsible for
    either completing of enqueuing the input Irp.  We only dismount a volume which
    has been locked.  The intent here is that someone has locked the volume (they are the
    only remaining handle).  We set the verify bit here and the user will close his handle.
    We will dismount a volume with no user's handles in the verify path.
Arguments:
    Irp - Supplies the Irp to process
Return Value:
    NTSTATUS - The return status for the operation
*/
NTSTATUS
UDFDismountVolume(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    NTSTATUS Status;
    KIRQL SavedIrql;

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
    BOOLEAN VcbAcquired = FALSE;
    PVCB Vcb;
    PFCB Fcb;
    PCCB Ccb;

    UDFPrint(("\n ### UDFDismountVolume ###\n\n"));

    // Decode the file object, the only type of opens we accept are
    // user volume opens.

    TYPE_OF_OPEN TypeOfOpen = UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    ASSERT_CCB(Ccb);
    
    // For UserVolumeOpen, Fcb is NULL (following FastFAT approach)
    if (TypeOfOpen != UserVolumeOpen) {
        ASSERT_FCB(Fcb);
    }

    if (!Ccb) {

        UDFPrintErr(("  !Ccb\n"));
        Irp->IoStatus.Information = 0;

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    // For UserVolumeOpen, get VCB from FileObject; for others, get from FCB
    if (TypeOfOpen == UserVolumeOpen) {
        Vcb = UDFGetVcbFromFileObject(IrpSp->FileObject);
    } else {
        Vcb = Fcb->Vcb;
    }
    ASSERT_VCB(Vcb);

    // Check for volume open
    if (TypeOfOpen != UserVolumeOpen || !(Ccb->Flags & UDF_CCB_VOLUME_OPEN)) {

        Irp->IoStatus.Information = 0;
        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    FsRtlNotifyVolumeEvent(IrpSp->FileObject, FSRTL_VOLUME_DISMOUNT);

    UDFCloseAllSystemDelayedInDir(Vcb, Vcb->RootIndexFcb->FileInfo);

#ifdef UDF_DELAYED_CLOSE
    UDFFspClose(Vcb);
#endif //UDF_DELAYED_CLOSE

    //  Acquire exclusive access to the Vcb.
    UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE );
    VcbAcquired = TRUE;

    _SEH2_TRY {

        //  Mark the volume as needs to be verified, but only do it if
        //  the vcb is locked by this handle and the volume is currently mounted.

        if (Vcb->VcbCondition != VcbMounted) {

            UDFReleaseResource( &(Vcb->VcbResource) );
            VcbAcquired = FALSE;

            Status = STATUS_VOLUME_DISMOUNTED;
        } else
        if (/*!(Vcb->VcbState & UDF_VCB_FLAGS_VOLUME_MOUNTED) ||*/
           !(Vcb->VcbState & VCB_STATE_LOCKED) ||
            (Vcb->VcbReference > (UDF_RESIDUAL_REFERENCE+1))) {

            Status = STATUS_NOT_LOCKED;
        } else
        if ((Vcb->VolumeLockFileObject != IrpSp->FileObject)) {

            Status = STATUS_INVALID_PARAMETER;

        } else {

            Vcb->Vpb->RealDevice->Flags |= DO_VERIFY_VOLUME;
            UDFDoDismountSequence(Vcb, FALSE);

            if (Vcb->VcbCondition != VcbDismountInProgress) {
                Vcb->VcbCondition = VcbInvalid;
            }

            Vcb->WriteSecurity = FALSE;
            // disable Eject Request Waiter if any
            UDFReleaseResource( &(Vcb->VcbResource) );
            VcbAcquired = FALSE;

            //  Set flag to tell the close path that we want to force dismount
            //  the volume when this handle is closed.
            SetFlag(Ccb->Flags, UDF_CCB_FLAG_DISMOUNT_ON_CLOSE);

            //  Set a flag in the VPB to let others know that direct volume access is allowed.
            IoAcquireVpbSpinLock(&SavedIrql);
            SetFlag( Vcb->Vpb->Flags, VPB_DIRECT_WRITES_ALLOWED );
            IoReleaseVpbSpinLock(SavedIrql);

            Status = STATUS_SUCCESS;
        }
    } _SEH2_FINALLY {
        //  Release all of our resources
        if (VcbAcquired)
            UDFReleaseResource( &(Vcb->VcbResource) );
    } _SEH2_END;

    if (!NT_SUCCESS(Status)) {
        FsRtlNotifyVolumeEvent(IrpSp->FileObject, FSRTL_VOLUME_DISMOUNT_FAILED);
    }

#if (NTDDI_VERSION >= NTDDI_WIN8)

    FsRtlDismountComplete(Vcb->TargetDeviceObject, Status);

#endif

    //  Complete the request if there haven't been any exceptions.
    Irp->IoStatus.Information = 0;

    UDFCompleteRequest(IrpContext, Irp, Status);
    return Status;
} // end UDFDismountVolume()

/*

    This routine returns the volume allocation bitmap.

        Input = the STARTING_LCN_INPUT_BUFFER data structure is passed in
            through the input buffer.
        Output = the VOLUME_BITMAP_BUFFER data structure is returned through
            the output buffer.

    We return as much as the user buffer allows starting the specified input
    LCN (trucated to a byte).  If there is no input buffer, we start at zero.

Arguments:

    Irp - Supplies the Irp being processed.

Return Value:

    NTSTATUS - The return status for the operation.

 */
NTSTATUS
UDFGetVolumeBitmap(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
//    NTSTATUS RC;

    PEXTENDED_IO_STACK_LOCATION IrpSp =
        (PEXTENDED_IO_STACK_LOCATION)IoGetCurrentIrpStackLocation( Irp );

    UDFPrint(("UDFGetVolumeBitmap\n"));

    TYPE_OF_OPEN TypeOfOpen;
    PFCB Fcb;
    PCCB Ccb;
    PVCB Vcb;
    ULONG BytesToCopy;
    ULONG TotalClusters;
    ULONG DesiredClusters;
    ULONG StartingCluster;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    LARGE_INTEGER StartingLcn;
    PVOLUME_BITMAP_BUFFER OutputBuffer;
    ULONG i, lim;
    PULONG FSBM;
//    PULONG Dest;
    ULONG LSh;

    // Decode the file object, the only type of opens we accept are
    // user volume opens.

    TypeOfOpen = UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    ASSERT_CCB(Ccb);
    ASSERT_FCB(Fcb);

    if (!Ccb) {

        UDFPrintErr(("  !Ccb\n"));
        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    Vcb = Fcb->Vcb;
    ASSERT_FCB(Fcb);

    InputBufferLength = IrpSp->Parameters.FileSystemControl.InputBufferLength;
    OutputBufferLength = IrpSp->Parameters.FileSystemControl.OutputBufferLength;

    OutputBuffer = (PVOLUME_BITMAP_BUFFER)UDFMapUserBuffer(Irp);

    if (!OutputBuffer) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_USER_BUFFER);
        return STATUS_INVALID_USER_BUFFER;
    }

    // Check for a minimum length on the input and output buffers.
    if ((InputBufferLength < sizeof(STARTING_LCN_INPUT_BUFFER)) ||
        (OutputBufferLength < sizeof(VOLUME_BITMAP_BUFFER))) {

        UDFUnlockCallersBuffer(IrpContext, Irp, OutputBuffer);

        UDFCompleteRequest(IrpContext, Irp, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //  Check if a starting cluster was specified.
    TotalClusters = Vcb->FSBM_BitCount;
    StartingLcn = ((PSTARTING_LCN_INPUT_BUFFER)IrpSp->Parameters.FileSystemControl.Type3InputBuffer)->StartingLcn;

    if (StartingLcn.HighPart || StartingLcn.LowPart >= TotalClusters) {

        UDFUnlockCallersBuffer(IrpContext, Irp, OutputBuffer);

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;

    } else {

        StartingCluster = StartingLcn.LowPart & ~7;
    }

    OutputBufferLength -= FIELD_OFFSET(VOLUME_BITMAP_BUFFER, Buffer);
    DesiredClusters = TotalClusters - StartingCluster;

    if (OutputBufferLength < (DesiredClusters + 7) / 8) {

        BytesToCopy = OutputBufferLength;
//        RC = STATUS_BUFFER_OVERFLOW;

    } else {

        BytesToCopy = (DesiredClusters + 7) / 8;
//        RC = STATUS_SUCCESS;
    }

    UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE );

    _SEH2_TRY {

        //  Fill in the fixed part of the output buffer
        OutputBuffer->StartingLcn.QuadPart = StartingCluster;
        OutputBuffer->BitmapSize.QuadPart = DesiredClusters;

        RtlZeroMemory( &OutputBuffer->Buffer[0], BytesToCopy );
        lim = BytesToCopy * 8;
        FSBM = (PULONG)(Vcb->FSBM_Bitmap);
        LSh = Vcb->LB2B_Bits;
//        Dest = (PULONG)(&OutputBuffer->Buffer[0]);

        for(i=StartingCluster & ~7; i<lim; i++) {
            if (UDFGetFreeBit(FSBM, i<<LSh))
                UDFSetFreeBit(FSBM, i);
        }

    } _SEH2_EXCEPT(UDFExceptionFilter(IrpContext, _SEH2_GetExceptionInformation())) {

        BrutePoint();
        UDFPrintErr(("UDFGetVolumeBitmap: Exception\n"));
//        UDFUnlockCallersBuffer(IrpContext, Irp, OutputBuffer);
        BrutePoint();
//        RC = UDFExceptionHandler(IrpContext, Irp);
        UDFReleaseResource(&(Vcb->VcbResource));
        UDFUnlockCallersBuffer(IrpContext, Irp, OutputBuffer);

        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
        return STATUS_INVALID_USER_BUFFER;
    } _SEH2_END;

    UDFReleaseResource(&(Vcb->VcbResource));

    UDFUnlockCallersBuffer(IrpContext, Irp, OutputBuffer);
    Irp->IoStatus.Information = FIELD_OFFSET(VOLUME_BITMAP_BUFFER, Buffer) +
                                BytesToCopy;

    UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);

    return STATUS_SUCCESS;


} // end UDFGetVolumeBitmap()


NTSTATUS
UDFGetRetrievalPointers(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP  Irp,
    IN ULONG Special
    )
{
    NTSTATUS RC;

    PEXTENDED_IO_STACK_LOCATION IrpSp =
        (PEXTENDED_IO_STACK_LOCATION)IoGetCurrentIrpStackLocation( Irp );
    PUDF_FILE_INFO FileInfo;

    ULONG InputBufferLength;
    ULONG OutputBufferLength;

    PRETRIEVAL_POINTERS_BUFFER OutputBuffer;
    PSTARTING_VCN_INPUT_BUFFER InputBuffer;

    LARGE_INTEGER StartingVcn;
    int64 AllocationSize;

    PCCB Ccb;
    PFCB Fcb;
    PVCB Vcb;

    PEXTENT_MAP SubMapping = NULL;
    ULONG SubExtInfoSz;
    ULONG i;
    ULONG LBS;
    ULONG LBSh;
    ULONG L2BSh;

    UDFPrint(("UDFGetRetrievalPointers\n"));

    UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    Vcb = Fcb->Vcb;

    ASSERT_CCB(Ccb);
    ASSERT_FCB(Fcb);
    ASSERT_VCB(Vcb);

    if (!Ccb) {

        UDFPrintErr(("  !Ccb\n"));
        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    //  Get the input and output buffer lengths and pointers.
    //  Initialize some variables.
    InputBufferLength = IrpSp->Parameters.FileSystemControl.InputBufferLength;
    OutputBufferLength = IrpSp->Parameters.FileSystemControl.OutputBufferLength;

    //OutputBuffer = (PRETRIEVAL_POINTERS_BUFFER)UDFGetCallersBuffer( IrpContext, Irp );
    if (Special) {
        OutputBuffer = (PRETRIEVAL_POINTERS_BUFFER)Irp->AssociatedIrp.SystemBuffer;
    } else {
        OutputBuffer = (PRETRIEVAL_POINTERS_BUFFER)Irp->UserBuffer;
    }
    InputBuffer = (PSTARTING_VCN_INPUT_BUFFER)IrpSp->Parameters.FileSystemControl.Type3InputBuffer;
    if (!InputBuffer) {
        InputBuffer = (PSTARTING_VCN_INPUT_BUFFER)OutputBuffer;
    }

    _SEH2_TRY {

        Irp->IoStatus.Information = 0;
        //  Check for a minimum length on the input and ouput buffers.
        if ((InputBufferLength < sizeof(STARTING_VCN_INPUT_BUFFER)) ||
            (OutputBufferLength < sizeof(RETRIEVAL_POINTERS_BUFFER))) {

            try_return( RC = STATUS_BUFFER_TOO_SMALL );
        }

        _SEH2_TRY {

            if (Irp->RequestorMode != KernelMode) {
                ProbeForRead( IrpSp->Parameters.FileSystemControl.Type3InputBuffer,
                              InputBufferLength,
                              sizeof(UCHAR) );
                ProbeForWrite( OutputBuffer, OutputBufferLength, sizeof(UCHAR) );
            }
            StartingVcn = InputBuffer->StartingVcn;

        } _SEH2_EXCEPT(Irp->RequestorMode != KernelMode ? EXCEPTION_EXECUTE_HANDLER: EXCEPTION_CONTINUE_SEARCH) {

            RC = _SEH2_GetExceptionCode();
            RC = FsRtlIsNtstatusExpected(RC) ?
                              RC : STATUS_INVALID_USER_BUFFER;
            try_return(RC);
        } _SEH2_END;

        switch(Special) {
        case 0:
            FileInfo = Fcb->FileInfo;
            break;
        case 1:
            FileInfo = Vcb->NonAllocFileInfo;
            break;
        default:
            try_return( RC = STATUS_INVALID_PARAMETER );
        }

        if (!FileInfo) {
            try_return( RC = STATUS_OBJECT_NAME_NOT_FOUND );
        }

        AllocationSize = UDFGetFileAllocationSize(Vcb, FileInfo);

        LBS   = Vcb->LBlockSize;
        LBSh  = Vcb->LBlockSizeBits;
        L2BSh = Vcb->LB2B_Bits;

        if (StartingVcn.HighPart ||
            StartingVcn.LowPart >= (ULONG)(AllocationSize >> LBSh)) {

            try_return( RC = STATUS_END_OF_FILE );
        }

        SubExtInfoSz = (OutputBufferLength - FIELD_OFFSET(RETRIEVAL_POINTERS_BUFFER, Extents[0])) / (sizeof(LARGE_INTEGER)*2);
        // re-use AllocationSize as NextVcn
        RC = UDFReadFileLocation__(Vcb, FileInfo, StartingVcn.QuadPart << LBSh,
                                   &SubMapping, &SubExtInfoSz, &AllocationSize);
        if (!NT_SUCCESS(RC))
            try_return(RC);

        OutputBuffer->ExtentCount = SubExtInfoSz;
        OutputBuffer->StartingVcn = StartingVcn;
        for(i=0; i<SubExtInfoSz; i++) {
            // assume, that
            // for not-allocated extents we have start Lba = -1
            // for not-recorded extents start Lba.LowPart contains real Lba, Lba.HighPart = 0x80000000
            // for recorded extents Lba.LowPart contains real Lba, Lba.HighPart = 0
            if (SubMapping[i].extLocation == LBA_NOT_ALLOCATED) {
                OutputBuffer->Extents[i].Lcn.QuadPart = (int64)(-1);
            } else
            if (SubMapping[i].extLocation & 0x80000000) {
                OutputBuffer->Extents[i].Lcn.LowPart = (SubMapping[i].extLocation & 0x7fffffff) >> L2BSh;
                OutputBuffer->Extents[i].Lcn.HighPart = 0x80000000;
            } else {
                OutputBuffer->Extents[i].Lcn.LowPart = SubMapping[i].extLocation >> L2BSh;
                OutputBuffer->Extents[i].Lcn.HighPart = 0;
            }
            // alignment for last sector
            SubMapping[i].extLength += LBS-1;
            StartingVcn.QuadPart += SubMapping[i].extLength   >> LBSh;
            OutputBuffer->Extents[i].NextVcn = StartingVcn;
        }

        Irp->IoStatus.Information = FIELD_OFFSET(RETRIEVAL_POINTERS_BUFFER, Extents[0]) + i * sizeof(LARGE_INTEGER) * 2;

try_exit:   NOTHING;
    } _SEH2_FINALLY {

        if (SubMapping)
            MyFreePool__(SubMapping);
    } _SEH2_END;

    UDFCompleteRequest(IrpContext, Irp, RC);

    return RC;
} // end UDFGetRetrievalPointers()


NTSTATUS
UDFIsVolumeDirty(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    PULONG VolumeState;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PCCB Ccb;
    PFCB Fcb;
    PVCB Vcb;

    UDFPrint(("UDFIsVolumeDirty\n"));

    //  Get a pointer to the output buffer.

    if (Irp->AssociatedIrp.SystemBuffer != NULL) {

        VolumeState = (PULONG)Irp->AssociatedIrp.SystemBuffer;

    } else {

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_USER_BUFFER);
        return STATUS_INVALID_USER_BUFFER;
    }

    //  Make sure the output buffer is large enough and then initialize
    //  the answer to be that the volume isn't dirty.

    if (IrpSp->Parameters.FileSystemControl.OutputBufferLength < sizeof(ULONG)) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    (*VolumeState) = 0;

    TYPE_OF_OPEN TypeOfOpen = UDFDecodeFileObject(IrpSp->FileObject, &Fcb, &Ccb);

    // For UserVolumeOpen, get VCB from FileObject; for others, get from FCB
    if (TypeOfOpen == UserVolumeOpen) {
        Vcb = UDFGetVcbFromFileObject(IrpSp->FileObject);
    } else {
        Vcb = Fcb->Vcb;
    }

    ASSERT_CCB(Ccb);
    
    // For UserVolumeOpen, Fcb is NULL (following FastFAT approach)
    if (TypeOfOpen != UserVolumeOpen) {
        ASSERT_FCB(Fcb);
    }
    ASSERT_VCB(Vcb);

    if (!Ccb) {
        UDFPrintErr(("  !Ccb\n"));
        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (TypeOfOpen != UserVolumeOpen || !(Ccb->Flags & UDF_CCB_VOLUME_OPEN)) {

        UDFPrintErr(("  !Volume\n"));
        UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (Vcb->VcbCondition != VcbMounted) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_VOLUME_DISMOUNTED);
        return STATUS_VOLUME_DISMOUNTED;
    }

    if (Vcb->origIntegrityType == INTEGRITY_TYPE_OPEN) {
        UDFPrint(("  Dirty\n"));
        (*VolumeState) |= VOLUME_IS_DIRTY;
    } else {
        UDFPrint(("  Clean\n"));
    }

    Irp->IoStatus.Information = sizeof(ULONG);

    UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;

} // end UDFIsVolumeDirty()


NTSTATUS
UDFInvalidateVolumes(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    )
{
    NTSTATUS RC;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    UDFPrint(("UDFInvalidateVolumes\n"));

    KIRQL SavedIrql;
    LUID TcbPrivilege = {SE_TCB_PRIVILEGE, 0};
    HANDLE Handle;
    PVCB Vcb;
    PLIST_ENTRY Link;
    PFILE_OBJECT FileToMarkBad;
    PDEVICE_OBJECT DeviceToMarkBad;

    Irp->IoStatus.Information = 0;

    //  Check for the correct security access.
    //  The caller must have the SeTcbPrivilege.
    if (IrpSp->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL &&
        IrpSp->MinorFunction == IRP_MN_USER_FS_REQUEST &&
        IrpSp->Parameters.FileSystemControl.FsControlCode == FSCTL_INVALIDATE_VOLUMES &&
        !SeSinglePrivilegeCheck(TcbPrivilege, Irp->RequestorMode)) {

        UDFCompleteRequest(IrpContext, Irp, STATUS_PRIVILEGE_NOT_HELD);
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    //  Try to get a pointer to the device object from the handle passed in.
#ifdef _WIN64
    if (IoIs32bitProcess(Irp)) {
        if (IrpSp->Parameters.FileSystemControl.InputBufferLength != sizeof(UINT32)) {

            UDFPrintErr(("UDFInvalidateVolumes: STATUS_INVALID_PARAMETER\n"));
            UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }

        Handle = (HANDLE)LongToHandle((*(UINT32*)Irp->AssociatedIrp.SystemBuffer));
    } else {
#endif
        if (IrpSp->Parameters.FileSystemControl.InputBufferLength != sizeof(HANDLE)) {

            UDFPrintErr(("UDFInvalidateVolumes: STATUS_INVALID_PARAMETER\n"));
            UDFCompleteRequest(IrpContext, Irp, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }

        Handle = *(HANDLE*)Irp->AssociatedIrp.SystemBuffer;
#ifdef _WIN64
    }
#endif

    RC = ObReferenceObjectByHandle( Handle,
                                    0,
                                    *IoFileObjectType,
                                    KernelMode,
                                    (PVOID*)&FileToMarkBad,
                                    NULL );

    if (!NT_SUCCESS(RC)) {

        UDFPrintErr(("UDFInvalidateVolumes: can't get handle, RC=%x\n", RC));
        UDFCompleteRequest(IrpContext, Irp, RC);
        return RC;
    }

    //  We only needed the pointer, not a reference.
    ObDereferenceObject(FileToMarkBad);

    //  Grab the DeviceObject from the FileObject.
    DeviceToMarkBad = FileToMarkBad->DeviceObject;

    // Acquire GlobalDataResource
    UDFAcquireResourceExclusive(&(UdfData.GlobalDataResource), TRUE);

    // Walk through all of the Vcb's attached to the global data.
    Link = UdfData.VcbQueue.Flink;

    while (Link != &(UdfData.VcbQueue)) {
        // Get 'next' Vcb
        Vcb = CONTAINING_RECORD( Link, VCB, NextVCB );
        // Move to the next link now since the current Vcb may be deleted.
        Link = Link->Flink;

        // Acquire Vcb resource
        UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE);

        if (Vcb->Vpb->RealDevice == DeviceToMarkBad) {

            // Take the VPB spinlock,  and look to see if this volume is the 
            // one currently mounted on the actual device.  If it is,  pull it 
            // off immediately.
            IoAcquireVpbSpinLock(&SavedIrql);

            if (DeviceToMarkBad->Vpb == Vcb->Vpb) {

                PVPB NewVpb = Vcb->SwapVpb;

                ASSERT(FlagOn(Vcb->Vpb->Flags, VPB_MOUNTED));
                ASSERT(NewVpb);

                RtlZeroMemory(NewVpb, sizeof(VPB));

                NewVpb->Type = IO_TYPE_VPB;
                NewVpb->Size = sizeof(VPB);
                NewVpb->RealDevice = DeviceToMarkBad;
                NewVpb->Flags = FlagOn(DeviceToMarkBad->Vpb->Flags, VPB_REMOVE_PENDING);

                DeviceToMarkBad->Vpb = NewVpb;
                Vcb->SwapVpb = NULL;
            }

            IoReleaseVpbSpinLock(SavedIrql);

            if (Vcb->VcbCondition != VcbDismountInProgress) {

                Vcb->VcbCondition = VcbInvalid;
            }

#ifdef UDF_DELAYED_CLOSE
            UDFPrint(("    UDFInvalidateVolumes:     set UDF_VCB_FLAGS_NO_DELAYED_CLOSE\n"));
            Vcb->VcbState |= UDF_VCB_FLAGS_NO_DELAYED_CLOSE;
            UDFReleaseResource(&(Vcb->VcbResource));
#endif //UDF_DELAYED_CLOSE

            if (Vcb->RootIndexFcb && Vcb->RootIndexFcb->FileInfo) {
                UDFPrint(("    UDFInvalidateVolumes:     UDFCloseAllSystemDelayedInDir\n"));
                RC = UDFCloseAllSystemDelayedInDir(Vcb, Vcb->RootIndexFcb->FileInfo);
                ASSERT(NT_SUCCESS(RC));
            }
#ifdef UDF_DELAYED_CLOSE
            UDFPrint(("    UDFInvalidateVolumes:     UDFCloseAllDelayed\n"));
            UDFFspClose(Vcb);
            //ASSERT(NT_SUCCESS(RC));
#endif //UDF_DELAYED_CLOSE

            UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE);

            UDFDoDismountSequence(Vcb, FALSE);
            UDFReleaseResource(&(Vcb->VcbResource));

            UDFPrint(("UDFInvalidateVolumes: Vcb %x dismounted\n", Vcb));
            break;
        } else {
            UDFPrint(("UDFInvalidateVolumes: skip Vcb %x\n", Vcb));
            UDFReleaseResource(&(Vcb->VcbResource));
        }

    }
    // Once we have processed all the mounted logical volumes, we can release
    // all acquired global resources and leave (in peace :-)
    UDFReleaseResource( &(UdfData.GlobalDataResource) );

    // drop volume completly
    UDFPrint(("UDFInvalidateVolumes: drop volume completly\n"));
    UDFAcquireResourceExclusive(&UdfData.GlobalDataResource, TRUE);
    UDFScanForDismountedVcb(IrpContext);
    UDFReleaseResource(&UdfData.GlobalDataResource);

    UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);

    UDFPrint(("UDFInvalidateVolumes: done\n"));
    return STATUS_SUCCESS;

} // end UDFInvalidateVolumes()
