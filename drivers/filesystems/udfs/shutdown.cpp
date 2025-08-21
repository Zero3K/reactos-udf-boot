////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*************************************************************************
*
* File: Shutdown.cpp
*
* Module: UDF File System Driver (Kernel mode execution only)
*
* Description:
*   Contains code to handle the "shutdown notification" dispatch entry point.
*
*************************************************************************/

#include            "udffs.h"

// define the file specific bug-check id
#define         UDF_BUG_CHECK_ID                UDF_FILE_SHUTDOWN



/*************************************************************************
*
* Function: UDFShutdown()
*
* Description:
*   All disk-based FSDs can expect to receive this shutdown notification
*   request whenever the system is about to be halted gracefully. If you
*   design and implement a network redirector, you must register explicitly
*   for shutdown notification by invoking the IoRegisterShutdownNotification()
*   routine from your driver entry.
*
*   Note that drivers that register to receive shutdown notification get
*   invoked BEFORE disk-based FSDs are told about the shutdown notification.
*
* Expected Interrupt Level (for execution) :
*
*  IRQL_PASSIVE_LEVEL
*
* Return Value: Irrelevant.
*
*************************************************************************/
NTSTATUS
NTAPI
UDFShutdown(
    PDEVICE_OBJECT   DeviceObject,       // the logical volume device object
    PIRP             Irp                 // I/O Request Packet
    )
{
    NTSTATUS         RC = STATUS_SUCCESS;
    PIRP_CONTEXT IrpContext = NULL;
    BOOLEAN          AreWeTopLevel = FALSE;

    UDFPrint(("UDFShutDown\n"));
//    BrutePoint();

    FsRtlEnterFileSystem();
    ASSERT(DeviceObject);
    ASSERT(Irp);

    // set the top level context
    AreWeTopLevel = UDFIsIrpTopLevel(Irp);
    //ASSERT(!UDFIsFSDevObj(DeviceObject));

    _SEH2_TRY {

        // get an IRP context structure and issue the request
        IrpContext = UDFCreateIrpContext(Irp, DeviceObject);
        if (IrpContext) {
            RC = UDFCommonShutdown(IrpContext, Irp);
        } else {

            UDFCompleteRequest(IrpContext, Irp, STATUS_INSUFFICIENT_RESOURCES);
            RC = STATUS_INSUFFICIENT_RESOURCES;
        }

    } _SEH2_EXCEPT(UDFExceptionFilter(IrpContext, _SEH2_GetExceptionInformation())) {

        RC = UDFProcessException(IrpContext, Irp);

        UDFLogEvent(UDF_ERROR_INTERNAL_ERROR, RC);
    } _SEH2_END;

    if (AreWeTopLevel) {
        IoSetTopLevelIrp(NULL);
    }

    FsRtlExitFileSystem();

    return(RC);
} // end UDFShutdown()


/*************************************************************************
*
* Function: UDFCommonShutdown()
*
* Description:
*   The actual work is performed here. Basically, all we do here is
*   internally invoke a flush on all mounted logical volumes. This, in
*   tuen, will result in all open file streams being flushed to disk.
*
* Expected Interrupt Level (for execution) :
*
*  IRQL_PASSIVE_LEVEL
*
* Return Value: Irrelevant
*
*************************************************************************/
NTSTATUS
UDFCommonShutdown(
    _Inout_ PIRP_CONTEXT IrpContext,
    _Inout_ PIRP Irp
    )
{
    KEVENT Event;
    NTSTATUS Status;
    PVCB Vcb;
    PLIST_ENTRY Link;
    BOOLEAN VcbPresent = TRUE;

    PAGED_CODE();

    // Make sure we don't get any pop-ups.

    SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_DISABLE_POPUPS );

    // Initialize an event for doing calls down to
    // our target device objects.

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    // Indicate that shutdown has started.

    SetFlag(UdfData.Flags, UDFS_FLAGS_SHUTDOWN);

    // Get everyone else out of the way

    UDFAcquireUdfData(IrpContext);

    _SEH2_TRY {

        // (a) Block all new "mount volume" requests by acquiring an appropriate
        //       global resource/lock.
        // (b) Go through your linked list of mounted logical volumes and for
        //       each such volume, do the following:
        //       (i) acquire the volume resource exclusively
        //       (ii) invoke UDFFlushLogicalVolume() (internally) to flush the
        //              open data streams belonging to the volume from the system
        //              cache
        //       (iii) Invoke the physical/virtual/logical target device object
        //              on which the volume is mounted and inform this device
        //              about the shutdown request (Use IoBuildSynchronouFsdRequest()
        //              to create an IRP with MajorFunction = IRP_MJ_SHUTDOWN that you
        //              will then issue to the target device object).
        //       (iv) Wait for the completion of the shutdown processing by the target
        //              device object
        //       (v) Release the VCB resource we will have acquired in (i) above.

        //  Now walk through all the mounted Vcb's and shutdown the target
        //  device objects.

        Link = UdfData.VcbQueue.Flink;

        while (Link != &(UdfData.VcbQueue)) {

            Vcb = CONTAINING_RECORD( Link, VCB, NextVCB );

            // Move to the next link now since the current Vcb may be deleted.

            Link = Link->Flink;

            // If we have already been called before for this volume
            // (and yes this does happen), skip this volume as no writes
            // have been allowed since the first shutdown.

            if (FlagOn(Vcb->VcbState, VCB_STATE_SHUTDOWN) ||
                (Vcb->VcbCondition != VcbMounted)) {

                continue;
            }

            UDFAcquireVcbExclusive(IrpContext, Vcb, FALSE);

            UDFFlushVolume(IrpContext, Vcb);

            ASSERT(!Vcb->OverflowQueueCount);

            {
            _SEH2_TRY {

                IO_STATUS_BLOCK Iosb;

                PIRP NewIrp = IoBuildSynchronousFsdRequest(IRP_MJ_SHUTDOWN,
                                                           Vcb->TargetDeviceObject,
                                                           NULL,
                                                           0,
                                                           NULL,
                                                           &Event,
                                                           &Iosb);

                if (NewIrp != NULL) {

                    if (NT_SUCCESS(IoCallDriver( Vcb->TargetDeviceObject, NewIrp ))) {

                        (VOID) KeWaitForSingleObject(&Event,
                                                     Executive,
                                                     KernelMode,
                                                     FALSE,
                                                     NULL);

                        KeClearEvent(&Event);
                    }
                }

            } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {

            } _SEH2_END;
            }

            ASSERT(!Vcb->OverflowQueueCount);

            SetFlag(Vcb->VcbState, VCB_STATE_SHUTDOWN);

            // Attempt to punch the volume down.

            VcbPresent = UDFCheckForDismount(IrpContext, Vcb, FALSE);

            if (VcbPresent) {

                UDFReleaseVcb(IrpContext, Vcb);
            }
        }

        // Once we have processed all the mounted logical volumes, we can release
        // all acquired global resources and leave (in peace :-)
        UDFReleaseUdfData(IrpContext);

        // Now, delete any device objects, etc. we may have created
        IoUnregisterFileSystem(UdfData.UDFDeviceObject_CD);
        if (UdfData.UDFDeviceObject_CD) {
            IoDeleteDevice(UdfData.UDFDeviceObject_CD);
            UdfData.UDFDeviceObject_CD = NULL;
        }
        IoUnregisterFileSystem(UdfData.UDFDeviceObject_HDD);
        if (UdfData.UDFDeviceObject_HDD) {
            IoDeleteDevice(UdfData.UDFDeviceObject_HDD);
            UdfData.UDFDeviceObject_HDD = NULL;
        }

        // free up any memory we might have reserved for zones/lookaside
        //  lists
        if (UdfData.Flags & UDF_DATA_FLAGS_ZONES_INITIALIZED) {
            UDFDestroyZones();
        }

        // delete the resource we may have initialized
        if (UdfData.Flags & UDF_DATA_FLAGS_RESOURCE_INITIALIZED) {
            // un-initialize this resource
            UDFDeleteResource(&UdfData.GlobalDataResource);
            ClearFlag(UdfData.Flags, UDF_DATA_FLAGS_RESOURCE_INITIALIZED);
        }

        Status = STATUS_SUCCESS;

    } _SEH2_FINALLY {

        UDFReleaseUdfData(IrpContext);

    } _SEH2_END; // end of "__finally" processing

    return STATUS_SUCCESS;
} // end UDFCommonShutdown()
