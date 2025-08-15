////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*************************************************************************
*
* File: Close.cpp
*
* Module: UDF File System Driver (Kernel mode execution only)
*
* Description:
*   Contains code to handle the "Close" dispatch entry point.
*
*************************************************************************/

#include            "udffs.h"

// define the file specific bug-check id
#define         UDF_BUG_CHECK_ID                UDF_FILE_CLOSE

typedef BOOLEAN      (*PCHECK_TREE_ITEM) (IN PUDF_FILE_INFO   FileInfo);
#define TREE_ITEM_LIST_GRAN 32

#define UDFCreateIrpContextLite(IC)  \
    ExAllocatePoolWithTag(NonPagedPool, sizeof( IRP_CONTEXT_LITE ), TAG_IRP_CONTEXT_LITE)

#define UDFFreeIrpContextLite(ICL)  \
    {                               \
        PVOID Pool = (PVOID)ICL;    \
        UDFFreePool(&Pool);         \
    }

NTSTATUS
UDFBuildTreeItemsList(
    IN PVCB               Vcb,
    IN PUDF_FILE_INFO     FileInfo,
    IN PCHECK_TREE_ITEM   CheckItemProc,
    IN PUDF_DATALOC_INFO** PassedList,
    IN PULONG             PassedListSize,
    IN PUDF_DATALOC_INFO** FoundList,
    IN PULONG             FoundListSize);

// callbacks, can't be __fastcall
BOOLEAN
UDFIsInDelayedCloseQueue(
    PUDF_FILE_INFO FileInfo);

BOOLEAN
UDFIsLastClose(
    PUDF_FILE_INFO FileInfo);

/*************************************************************************
*
* Function: UDFClose()
*
* Description:
*   The I/O Manager will invoke this routine to handle a close
*   request
*
* Expected Interrupt Level (for execution) :
*
*  IRQL_PASSIVE_LEVEL (invocation at higher IRQL will cause execution
*   to be deferred to a worker thread context)
*
* Return Value: STATUS_SUCCESS
*
*************************************************************************/
NTSTATUS
NTAPI
UDFClose(
    PDEVICE_OBJECT  DeviceObject,  // the logical volume device object
    PIRP            Irp            // I/O Request Packet
    )
{
    NTSTATUS            RC = STATUS_SUCCESS;
    PIRP_CONTEXT IrpContext = NULL;
    BOOLEAN             AreWeTopLevel = FALSE;

    AdPrint(("UDFClose: \n"));

    FsRtlEnterFileSystem();
    ASSERT(DeviceObject);
    ASSERT(Irp);

    // set the top level context
    AreWeTopLevel = UDFIsIrpTopLevel(Irp);

    _SEH2_TRY {

        // get an IRP context structure and issue the request
        IrpContext = UDFCreateIrpContext(Irp, DeviceObject);
        ASSERT(IrpContext);

        RC = UDFCommonClose(IrpContext, Irp, FALSE);

    } _SEH2_EXCEPT(UDFExceptionFilter(IrpContext, _SEH2_GetExceptionInformation())) {

        RC = UDFProcessException(IrpContext, Irp);

        UDFLogEvent(UDF_ERROR_INTERNAL_ERROR, RC);
    } _SEH2_END;

    if (AreWeTopLevel) {
        IoSetTopLevelIrp(NULL);
    }

    FsRtlExitFileSystem();

    return(RC);
}




/*************************************************************************
*
* Function: UDFCommonClose()
*
* Description:
*   The actual work is performed here. This routine may be invoked in one'
*   of the two possible contexts:
*   (a) in the context of a system worker thread
*   (b) in the context of the original caller
*
* Expected Interrupt Level (for execution) :
*
*  IRQL_PASSIVE_LEVEL
*
* Return Value: must be STATUS_SUCCESS
*
*************************************************************************/
NTSTATUS
UDFCommonClose(
    PIRP_CONTEXT IrpContext,
    PIRP             Irp,
    BOOLEAN          CanWait
    )
{
    NTSTATUS                RC = STATUS_SUCCESS;
    PIO_STACK_LOCATION      IrpSp = NULL;
    PFILE_OBJECT            FileObject = NULL;
    PFCB                    Fcb = NULL;
    PCCB                    Ccb = NULL;
    PVCB                    Vcb = NULL;
    BOOLEAN                 AcquiredVcb = FALSE;
    BOOLEAN                 AcquiredGD = FALSE;
    PUDF_FILE_INFO          fi;
    ULONG                   i = 0;
    BOOLEAN                 PostRequest = FALSE;
    TYPE_OF_OPEN            TypeOfOpen;
    ULONG UserReference = 0;

#ifdef UDF_DBG
    UNICODE_STRING          CurName;
    PDIR_INDEX_HDR          DirNdx;
#endif

    AdPrint(("UDFCommonClose: \n"));

    PAGED_CODE();

    ASSERT_IRP_CONTEXT(IrpContext);
    ASSERT_OPTIONAL_IRP(Irp);

    //  If we were called with our file system device object instead of a
    //  volume device object, just complete this request with STATUS_SUCCESS.

    if (IrpContext->Vcb == NULL) {

        UDFCompleteRequest( IrpContext, Irp, STATUS_SUCCESS );
        return STATUS_SUCCESS;
    }

    if (Irp) {

        // If this is the first (IOManager) request
        // First, get a pointer to the current I/O stack location

        IrpSp = IoGetCurrentIrpStackLocation(Irp);

        FileObject = IrpSp->FileObject;

        //  Decode the file object to get the type of open and Fcb/Ccb.

        TypeOfOpen = UDFDecodeFileObject(FileObject, &Fcb, &Ccb);

        //  No work to do for unopened file objects.

        if (TypeOfOpen == UnopenedFileObject) {

            UDFCompleteRequest(IrpContext, Irp, STATUS_SUCCESS);

            return STATUS_SUCCESS;
        }

        ASSERT_CCB(Ccb);

    } else {

        // If this is a queued call (for our dispatch)
        // Get saved Fcb address
        Fcb = IrpContext->Fcb;
    }

    Vcb = Fcb->Vcb;

    ASSERT_FCB(Fcb);
    ASSERT_VCB(Vcb);

    _SEH2_TRY {

        // Steps we shall take at this point are:
        // (a) Acquire the VCB shared
        // (b) Acquire the FCB's CCB list exclusively
        // (c) Delete the CCB structure (free memory)
        // (d) If this is the last close, release the FCB structure
        //       (unless we keep these around for "delayed close" functionality.
        // Note that it is often the case that the close dispatch entry point is invoked
        // in the most inconvenient of situations (when it is not possible, for example,
        // to safely acquire certain required resources without deadlocking or waiting).
        // Therefore, be extremely careful in implementing this close dispatch entry point.
        // Also note that we do not have the option of returning a failure code from the
        // close dispatch entry point; the system expects that the close will always succeed.

        UDFAcquireResourceShared(&(Vcb->VcbResource), TRUE);
        AcquiredVcb = TRUE;

        // Is this is the first (IOManager) request ?
        if (Irp) {

            UserReference = 1;
            // remember the number of incomplete Close requests
            InterlockedIncrement((PLONG)&(Fcb->CcbCount));
            // we can release CCB in any case
            UDFDeleteCcb(Ccb);
            FileObject->FsContext2 = NULL;
        }

#ifdef UDF_DELAYED_CLOSE
        // check if this is the last Close (no more Handles)
        // and try to Delay it....
        if ((Fcb->FcbState & UDF_FCB_DELAY_CLOSE) &&
           Vcb->VcbCondition == VcbMounted &&
          !(Vcb->VcbState & UDF_VCB_FLAGS_NO_DELAYED_CLOSE) &&
          !(Fcb->FcbCleanup)) {
            UDFReleaseResource(&(Vcb->VcbResource));
            AcquiredVcb = FALSE;
            if ((RC = UDFQueueClose(IrpContext, Fcb, UserReference)) == STATUS_SUCCESS)
                try_return(RC = STATUS_SUCCESS);
            // do standard Close if we can't Delay this opeartion
            AdPrint(("   Cant queue Close Irp, status=%x\n", RC));
        }
#endif //UDF_DELAYED_CLOSE

        if (Irp) {
            // We should post actual procesing if the caller does not want to block
            if (!CanWait) {
                AdPrint(("   post Close Irp\n"));
                PostRequest = TRUE;
                try_return(RC = STATUS_SUCCESS);
            }
        }

        // Close request is near completion, Vcb is acquired.
        // Now we can safely decrease CcbCount, because no Rename
        // operation can run until Vcb release.
        InterlockedDecrement((PLONG)&(Fcb->CcbCount));

        UDFInterlockedDecrement((PLONG)&(Vcb->VcbReference));

        if (!i || (Fcb == Fcb->Vcb->VolumeDasdFcb)) {

            AdPrint(("UDF: Closing volume\n"));
            AdPrint(("UDF: ReferenceCount:  %x\n",Fcb->FcbReference));

            if (Vcb->VcbReference > UDF_RESIDUAL_REFERENCE) {
                ASSERT(Fcb == Fcb->Vcb->VolumeDasdFcb);
                UDFInterlockedDecrement((PLONG)&Fcb->FcbReference);
                ASSERT(Fcb);

                try_return(RC = STATUS_SUCCESS);
            }

            UDFInterlockedIncrement((PLONG)&Vcb->VcbReference);

            if (AcquiredVcb) {
                UDFReleaseResource(&(Vcb->VcbResource));
                AcquiredVcb = FALSE;
            } else {
                BrutePoint();
            }
            // Acquire GlobalDataResource
            UDFAcquireResourceExclusive(&UdfData.GlobalDataResource, TRUE);
            AcquiredGD = TRUE;
//            // Acquire Vcb
            UDFAcquireResourceExclusive(&Vcb->VcbResource, TRUE);
            AcquiredVcb = TRUE;

            UDFInterlockedDecrement((PLONG)&Vcb->VcbReference);


            ASSERT(Fcb == Fcb->Vcb->VolumeDasdFcb);
            UDFInterlockedDecrement((PLONG)&Fcb->FcbReference);
            ASSERT(Fcb);

            //AdPrint(("UDF: Closing volume, reset driver (e.g. stop BGF)\n"));
            //UDFResetDeviceDriver(Vcb, Vcb->TargetDeviceObject, FALSE);

            if (Vcb->VcbCondition == VcbDismountInProgress ||
               Vcb->VcbCondition == VcbInvalid ||
             ((Vcb->VcbCondition == VcbNotMounted) && (Vcb->VcbReference <= UDF_RESIDUAL_REFERENCE))) {
                // Try to KILL dismounted volume....
                // w2k requires this, NT4 - recomends
                AcquiredVcb = UDFCheckForDismount(IrpContext, Vcb, TRUE);
            }

            try_return(RC = STATUS_SUCCESS);
        }

        fi = Fcb->FileInfo;
#ifdef UDF_DBG
        if (!fi) {
            BrutePoint();
        }

        DirNdx = UDFGetDirIndexByFileInfo(fi);
        if (DirNdx) {
            CurName = UDFDirIndex(DirNdx,fi->Index)->FName;
            if (CurName.Length) {
                AdPrint(("Closing file: %wZ %8.8x\n", &CurName, FileObject));
            } else {
                AdPrint(("Closing file: ??? \n"));
            }
        }
        AdPrint(("UDF: ReferenceCount:  %x\n",Fcb->FcbReference));
#endif // UDF_DBG
        // try to clean up as long chain as it is possible
        UDFTeardownStructures(IrpContext, fi->Fcb, NULL);

try_exit: NOTHING;

    } _SEH2_FINALLY {

        if (AcquiredVcb) {
            UDFReleaseResource(&(Vcb->VcbResource));
        }
        if (AcquiredGD) {
            UDFReleaseResource(&(UdfData.GlobalDataResource));
        }

        // Post IRP if required
        if (PostRequest) {

            // Perform the post operation & complete the IRP
            // if this is first call of UDFCommonClose
            // and will return STATUS_SUCCESS back to us
            IrpContext->Irp = NULL;
            IrpContext->Fcb = Fcb;
            UDFPostRequest(IrpContext, NULL);
        }

        if (!_SEH2_AbnormalTermination()) {
            // If this is not async close complete the IRP
            if (Irp) {

                UDFCompleteRequest(NULL, Irp, STATUS_SUCCESS);
            }
            // Free up the Irp Context
            if (!PostRequest)
                UDFCleanupIrpContext(IrpContext);
        }

    } _SEH2_END; // end of "__finally" processing

    return STATUS_SUCCESS ;
} // end UDFCommonClose()

/*
    This routine walks through the tree to RootDir & kills all unreferenced
    structures....
    imho, Useful feature
 */
_Requires_lock_held_(_Global_critical_region_)
VOID
UDFTeardownStructures(
    _In_ PIRP_CONTEXT IrpContext,
    _Inout_ PFCB StartingFcb,
    _Out_ PBOOLEAN RemovedStartingFcb
    )
{
    PVCB Vcb = StartingFcb->Vcb;
    PFCB CurrentFcb = StartingFcb;
    PFCB ParentFcb = NULL;
    PUDF_FILE_INFO fi = StartingFcb->FileInfo;
    PUDF_FILE_INFO ParentFI;
    LONG RefCount;
    BOOLEAN Delete = FALSE;

    ValidateFileInfo(CurrentFcb->FileInfo);
    AdPrint(("UDFCleanUpFcbChain\n"));

    //TODO:
    //ASSERT_EXCLUSIVE_FCB(StartingFcb);
    //ASSERT_SHARED_VCB(Vcb);

    if (RemovedStartingFcb) {
        *RemovedStartingFcb = FALSE;
    }

    // cleanup parent chain (if any & unused)
    while(fi) {

        // acquire parent
        if ((ParentFI = fi->ParentFile)) {

            ASSERT(fi->Fcb);
            ParentFcb = fi->Fcb->ParentFcb;
            ASSERT(ParentFcb);

            UDF_CHECK_PAGING_IO_RESOURCE(ParentFcb);
            UDFAcquireResourceExclusive(&ParentFcb->FcbNonpaged->FcbResource,TRUE);

        }

        CurrentFcb = fi->Fcb;
        ASSERT_FCB(CurrentFcb);

        // acquire current file/dir
        // we must assure that no more threads try to re-use this object
#ifdef UDF_DBG
        _SEH2_TRY {
#endif // UDF_DBG
            UDF_CHECK_PAGING_IO_RESOURCE(CurrentFcb);
            UDFAcquireResourceExclusive(&CurrentFcb->FcbNonpaged->FcbResource,TRUE);
#ifdef UDF_DBG
        } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
            BrutePoint();
            if (ParentFI) {
                UDF_CHECK_PAGING_IO_RESOURCE(ParentFcb);
                UDFReleaseResource(&ParentFcb->FcbNonpaged->FcbResource);
            }
            break;
        } _SEH2_END;
#endif // UDF_DBG
        ASSERT(CurrentFcb->FcbReference > fi->RefCount);
        // Decrement the reference count for this FCB
#ifdef UDF_DBG
        if (CurrentFcb) {
            ASSERT(CurrentFcb->FcbReference);
            RefCount = UDFInterlockedDecrement((PLONG)&CurrentFcb->FcbReference);
        } else {
            BrutePoint();
        }
        ASSERT(CurrentFcb->FcbCleanup <= CurrentFcb->FcbReference);
#else
        RefCount = UDFInterlockedDecrement((PLONG)&CurrentFcb->FcbReference);
#endif

        // ...and delete if it has gone

        if (!RefCount && !CurrentFcb->FcbCleanup) {

            // no more references... current file/dir MUST DIE!!!
            if (Delete) {
/*                if (!(Fcb->FCBFlags & UDF_FCB_DIRECTORY)) {
                    // set file size to zero (for UdfInfo package)
                    // we should not do this for directories
                    UDFResizeFile__(Vcb, fi, 0);
                }*/
                UDFReferenceFile__(fi);
                ASSERT(CurrentFcb->FcbReference < fi->RefCount);
                UDFFlushFile__(IrpContext, Vcb, fi);
                UDFUnlinkFile__(IrpContext, Vcb, fi, TRUE);
                UDFCloseFile__(IrpContext, Vcb, fi);
                ASSERT(CurrentFcb->FcbReference == fi->RefCount);
                CurrentFcb->FcbState |= UDF_FCB_DELETED;
                Delete = FALSE;
            }
            else if (!(CurrentFcb->FcbState & UDF_FCB_DELETED)) {
                UDFFlushFile__(IrpContext, Vcb, fi);
            } else {
//                BrutePoint();
            }

            // check if we should try to delete Parent for the next time
            if (CurrentFcb->FcbState & UDF_FCB_DELETE_PARENT)
                Delete = TRUE;

            // remove references to OS-specific structures
            // to let UDF_INFO release FI & Co
            fi->Fcb = NULL;
            fi->Dloc->CommonFcb = NULL;

            if (UDFCleanUpFile__(Vcb, fi) == (UDF_FREE_FILEINFO | UDF_FREE_DLOC)) {
                // Check, if we can uninitialize & deallocate CommonFcb part
                // kill some cross links
                CurrentFcb->FileInfo = NULL;
                // release allocated resources
                // Obviously, it is a good time & place to release
                // CommonFcb structure

//                NtReqFcb->NtReqFCBFlags &= ~UDF_NTREQ_FCB_VALID;
                // Unitialize byte-range locks support structure
                if (CurrentFcb->FileLock != NULL) {

                    FsRtlFreeFileLock(CurrentFcb->FileLock);
                }

                FsRtlTeardownPerStreamContexts(&CurrentFcb->Header);

                // Remove resources
                UDF_CHECK_PAGING_IO_RESOURCE(CurrentFcb);
                UDFReleaseResource(&CurrentFcb->FcbNonpaged->FcbResource);
                if (CurrentFcb->Header.Resource) {
                    UDFDeleteResource(&CurrentFcb->FcbNonpaged->FcbResource);
                    UDFDeleteResource(&CurrentFcb->FcbNonpaged->FcbPagingIoResource);
                }

                CurrentFcb->Header.Resource =
                CurrentFcb->Header.PagingIoResource = NULL;

                UDFPrint(("UDFRelease Fcb: %x\n", CurrentFcb));

                // remove some references & free Fcb structure
                CurrentFcb->ParentFcb = NULL;
                UDFCleanUpFCB(CurrentFcb);
                MyFreePool__(fi);

                // get pointer to parent FCB
                fi = ParentFI;
                // free old parent's resource...
                if (fi) {
                    UDF_CHECK_PAGING_IO_RESOURCE(ParentFcb);
                    UDFReleaseResource(&ParentFcb->FcbNonpaged->FcbResource);
                }
            } else {
                // Stop cleaning up

                // Restore pointers
                fi->Fcb = CurrentFcb;
                fi->Dloc->CommonFcb = CurrentFcb;
                // free all acquired resources
                UDF_CHECK_PAGING_IO_RESOURCE(CurrentFcb);
                UDFReleaseResource(&CurrentFcb->FcbNonpaged->FcbResource);
                fi = ParentFI;
                if (fi) {
                    UDF_CHECK_PAGING_IO_RESOURCE(ParentFcb);
                    UDFReleaseResource(&ParentFcb->FcbNonpaged->FcbResource);
                }
                // If we have dereferenced the current file & it is still in use
                // then it isn't worth walking down the tree
                // 'cause in this case all the rest files are also used
                break;
//                AdPrint(("Stop on referenced File/Dir\n"));
            }
        } else {
            // we get to referenced file/dir. Stop search & release resource
            UDF_CHECK_PAGING_IO_RESOURCE(CurrentFcb);
            UDFReleaseResource(&CurrentFcb->FcbNonpaged->FcbResource);
            if (ParentFI) {
                UDF_CHECK_PAGING_IO_RESOURCE(ParentFcb);
                UDFReleaseResource(&ParentFcb->FcbNonpaged->FcbResource);
            }
            Delete = FALSE;
            break;
            fi = ParentFI;
        }
    }

    if (RemovedStartingFcb) {
        *RemovedStartingFcb = (CurrentFcb != StartingFcb);
    }

} // end UDFCleanUpFcbChain()

VOID
UDFDoDelayedClose(
    IN PIRP_CONTEXT_LITE NextIrpContextLite
    )
{
    IRP_CONTEXT StackIrpContext;

    AdPrint(("  UDFDoDelayedClose\n"));
    UDFInitializeStackIrpContextFromLite(&StackIrpContext, NextIrpContextLite);
    MyFreePool__(NextIrpContextLite);
    StackIrpContext.Fcb->IrpContextLite = NULL;
    StackIrpContext.Fcb->FcbState &= ~UDF_FCB_DELAY_CLOSE;
    UDFCommonClose(&StackIrpContext, NULL, TRUE);
} // end UDFDoDelayedClose()

PIRP_CONTEXT
UDFRemoveClose(
    _In_opt_ PVCB Vcb
    )

/*++

Routine Description:

Arguments:

    This routine is called to scan the async and delayed close queues looking
    for a suitable entry.  If the Vcb is specified then we scan both queues
    looking for an entry with the same Vcb.  Otherwise we will look in the
    async queue first for any close item.  If none found there then we look
    in the delayed close queue provided that we have triggered the delayed
    close operation.

Return Value:

    PIRP_CONTEXT - NULL if no work item found.  Otherwise it is the pointer to
        either the IrpContext or IrpContextLite for this request.

--*/

{
    PIRP_CONTEXT IrpContext = NULL;
    PIRP_CONTEXT NextIrpContext;
    PIRP_CONTEXT_LITE NextIrpContextLite;

    PLIST_ENTRY Entry;

    PAGED_CODE();

    ASSERT_OPTIONAL_VCB(Vcb);

    // Lock the UdfData to perform the scan.

    UDFLockUdfData();

    //  First check the list of async closes.

    Entry = UdfData.AsyncCloseQueue.Flink;

    while (Entry != &UdfData.AsyncCloseQueue) {

        // Extract the IrpContext.

        NextIrpContext = CONTAINING_RECORD( Entry,
                                            IRP_CONTEXT,
                                            WorkQueueItem.List );

        // If no Vcb was specified or this Vcb is for our volume
        // then perform the close.

        if (!ARGUMENT_PRESENT(Vcb) || (NextIrpContext->Vcb == Vcb)) {

            RemoveEntryList( Entry );
            UdfData.AsyncCloseCount -= 1;

            IrpContext = NextIrpContext;
            break;
        }

        // Move to the next entry.

        Entry = Entry->Flink;
    }

    //  If we didn't find anything look through the delayed close
    //  queue.
    //
    //  We will only check the delayed close queue if we were given
    //  a Vcb or the delayed close operation is active.

    if ((IrpContext == NULL) &&
        (ARGUMENT_PRESENT( Vcb ) ||
        (UdfData.ReduceDelayedClose &&
        (UdfData.DelayedCloseCount > UdfData.MinDelayedCloseCount)))) {

        Entry = UdfData.DelayedCloseQueue.Flink;

        while (Entry != &UdfData.DelayedCloseQueue) {

            // Extract the IrpContext.

            NextIrpContextLite = CONTAINING_RECORD( Entry,
                                                    IRP_CONTEXT_LITE,
                                                    DelayedCloseLinks );

            //  If no Vcb was specified or this Vcb is for our volume
            //  then perform the close.

            if (!ARGUMENT_PRESENT(Vcb) || (NextIrpContextLite->Fcb->Vcb == Vcb)) {

                RemoveEntryList(Entry);
                UdfData.DelayedCloseCount -= 1;

                IrpContext = (PIRP_CONTEXT) NextIrpContextLite;
                break;
            }

            //
            //  Move to the next entry.
            //

            Entry = Entry->Flink;
        }
    }

    // If the Vcb wasn't specified and we couldn't find an entry
    // then turn off the Fsp thread.

    if (!ARGUMENT_PRESENT( Vcb ) && (IrpContext == NULL)) {

        UdfData.FspCloseActive = FALSE;
        UdfData.ReduceDelayedClose = FALSE;
    }

    // Unlock the UdfData.

    UDFUnlockUdfData();

    return IrpContext;
}

VOID
UDFInitializeStackIrpContext(
    _Out_ PIRP_CONTEXT IrpContext,
    _In_ PIRP_CONTEXT_LITE IrpContextLite
    )

/*++

Routine Description:

    This routine is called to initialize an IrpContext for the current
    CDFS request.  The IrpContext is on the stack and we need to initialize
    it for the current request.  The request is a close operation.

Arguments:

    IrpContext - IrpContext to initialize.

    IrpContextLite - Structure containing the details of this request.

Return Value:

    None

--*/

{
    PAGED_CODE();

    // Zero and then initialize the structure.

    RtlZeroMemory( IrpContext, sizeof( IRP_CONTEXT ));

    // Set the proper node type code and node byte size

    IrpContext->NodeIdentifier.NodeTypeCode = UDF_NODE_TYPE_IRP_CONTEXT;
    IrpContext->NodeIdentifier.NodeByteSize = sizeof(IRP_CONTEXT);

    // Note that this is from the stack.

    SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_ON_STACK );

    // Copy RealDevice for workque algorithms.

    IrpContext->TreeLength = IrpContextLite->TreeLength;
    IrpContext->RealDevice = IrpContextLite->RealDevice;

    // The Vcb is found in the Fcb.

    IrpContext->Vcb = IrpContextLite->Fcb->Vcb;

    // Major/Minor Function codes

    IrpContext->MajorFunction = IRP_MJ_CLOSE;

    // Set the wait parameter

    SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);

    return;
}

_Requires_lock_held_(_Global_critical_region_)
BOOLEAN
UDFCommonClosePrivate(
    _In_ PIRP_CONTEXT IrpContext,
    _In_ PVCB Vcb,
    _In_ PFCB Fcb,
    _In_ ULONG UserReference,
    _In_ BOOLEAN FromFsd
)

/*++

Routine Description:

    This is the worker routine for the close operation.  We can be called in
    an Fsd thread or from a worker Fsp thread.  If called from the Fsd thread
    then we acquire the resources without waiting.  Otherwise we know it is
    safe to wait.

    We check to see whether we should post this request to the delayed close
    queue.  If we are to process the close here then we acquire the Vcb and
    Fcb.  We will adjust the counts and call our teardown routine to see
    if any of the structures should go away.

Arguments:

    Vcb - Vcb for this volume.

    Fcb - Fcb for this request.

    UserReference - Number of user references for this file object.  This is
        zero for an internal stream.

    FromFsd - This request was called from an Fsd thread.  Indicates whether
        we should wait to acquire resources.

    DelayedClose - Address to store whether we should try to put this on
        the delayed close queue.  Ignored if this routine can process this
        close.

Return Value:

    BOOLEAN - TRUE if this thread processed the close, FALSE otherwise.

--*/

{
    BOOLEAN RemovedFcb;

    PAGED_CODE();

    ASSERT_IRP_CONTEXT(IrpContext);
    ASSERT_FCB(Fcb);

    //  Try to acquire the Vcb and Fcb.  If we can't acquire them then return
    // and let our caller know he should post the request to the async
    // queue.

    if (UDFAcquireVcbShared(IrpContext, Vcb, FromFsd)) {

        if (!UDFAcquireFcbExclusive(IrpContext, Fcb, FromFsd)) {

            // We couldn't get the Fcb.  Release the Vcb and let our caller
            // know to post this request.

            UDFReleaseVcb(IrpContext, Vcb);
            return FALSE;
        }

    // We didn't get the Vcb.  Let our caller know to post this request.

    } else {

        return FALSE;
    }

    // Lock the Vcb and decrement the reference counts.

    UDFLockVcb(IrpContext, Vcb);
    UDFDecrementReferenceCounts(IrpContext, Fcb, 1, UserReference);
    UDFUnlockVcb(IrpContext, Vcb);

    //  Call our teardown routine to see if this object can go away.
    //  If we don't remove the Fcb then release it.

    UDFTeardownStructures(IrpContext, Fcb, &RemovedFcb);

    if (!RemovedFcb) {

        UDFReleaseFcb(IrpContext, Fcb);
    }
    else {
        _Analysis_assume_lock_not_held_(Fcb->FcbNonpaged->FcbResource);
    }

    //  Release the Vcb and return to our caller.  Let him know we completed
    //  this request.

    UDFReleaseVcb(IrpContext, Vcb);

    return TRUE;
}


VOID
NTAPI
UDFFspClose(
    _In_opt_ PVCB Vcb
    )

/*++

Routine Description:

    This routine is called to process the close queues in the UdfData.  If the
    Vcb is passed then we want to remove all of the closes for this Vcb.
    Otherwise we will do as many of the delayed closes as we need to do.

Arguments:

    Vcb - If specified then we are looking for all of the closes for the
        given Vcb.

Return Value:

    None

--*/

{
    PIRP_CONTEXT IrpContext;
    IRP_CONTEXT StackIrpContext = {0};

    THREAD_CONTEXT ThreadContext = {0};

    PFCB Fcb;
    ULONG UserReference;

    ULONG VcbHoldCount = 0;
    PVCB CurrentVcb = NULL;

    BOOLEAN PotentialVcbTeardown = FALSE;

    PAGED_CODE();

    ASSERT_OPTIONAL_VCB(Vcb);

    FsRtlEnterFileSystem();

    // Continue processing until there are no more closes to process.

    while ((IrpContext = UDFRemoveClose(Vcb)) != NULL) {

        // If we don't have an IrpContext then use the one on the stack.
        // Initialize it for this request.

        if (SafeNodeType(IrpContext) != UDF_NODE_TYPE_IRP_CONTEXT) {

            // Update the local values from the IrpContextLite.

            Fcb = ((PIRP_CONTEXT_LITE)IrpContext)->Fcb;
            UserReference = ((PIRP_CONTEXT_LITE)IrpContext)->UserReference;

            // Update the stack irp context with the values from the
            // IrpContextLite.

            UDFInitializeStackIrpContext(&StackIrpContext,
                                         (PIRP_CONTEXT_LITE)IrpContext);

            // Free the IrpContextLite.

            UDFFreeIrpContextLite((PIRP_CONTEXT_LITE)IrpContext);

            //  Remember we have the IrpContext from the stack.

            IrpContext = &StackIrpContext;

        //  Otherwise cleanup the existing IrpContext.

        } else {

            //  Remember the Fcb and user reference count.

            Fcb = (PFCB) IrpContext->Irp;
            IrpContext->Irp = NULL;

            UserReference = (ULONG) IrpContext->ExceptionStatus;
            IrpContext->ExceptionStatus = STATUS_SUCCESS;
        }

        _Analysis_assume_(Fcb != NULL && Fcb->Vcb != NULL);

        // We have an IrpContext.  Now we need to set the top level thread
        // context.

        SetFlag(IrpContext->Flags, IRP_CONTEXT_FSP_FLAGS);

        //  If we were given a Vcb then there is a request on top of this.

        if (ARGUMENT_PRESENT(Vcb)) {

            ClearFlag(IrpContext->Flags,
                      IRP_CONTEXT_FLAG_TOP_LEVEL | IRP_CONTEXT_FLAG_TOP_LEVEL_UDFS);
        }

        UDFSetThreadContext(IrpContext, &ThreadContext);

        //  If we have hit the maximum number of requests to process without
        //  releasing the Vcb then release the Vcb now.  If we are holding
        //  a different Vcb to this one then release the previous Vcb.
        //
        //  In either case acquire the current Vcb.
        //
        //  We use the MinDelayedCloseCount from the CdData since it is
        //  a convenient value based on the system size.  Only thing we are trying
        //  to do here is prevent this routine starving other threads which
        //  may need this Vcb exclusively.
        //
        //  Note that the check for potential teardown below is unsafe.  We'll 
        //  repeat later within the cddata lock.

        PotentialVcbTeardown = !ARGUMENT_PRESENT( Vcb ) &&
                               (Fcb->Vcb->VcbCondition != VcbMounted) &&
                               (Fcb->Vcb->VcbCondition != VcbMountInProgress) &&
                               (Fcb->Vcb->VcbCleanup == 0);

        if (PotentialVcbTeardown ||
            (VcbHoldCount > UdfData.MinDelayedCloseCount) ||
            (Fcb->Vcb != CurrentVcb)) {

            if (CurrentVcb != NULL) {

                UDFReleaseVcb(IrpContext, CurrentVcb);
            }

            if (PotentialVcbTeardown) {

                UDFAcquireUdfData(IrpContext);

                //  Repeat the checks with global lock held.  The volume could have
                //  been remounted while we didn't hold the lock.

                PotentialVcbTeardown = !ARGUMENT_PRESENT( Vcb ) &&
                                       (Fcb->Vcb->VcbCondition != VcbMounted) &&
                                       (Fcb->Vcb->VcbCondition != VcbMountInProgress) &&
                                       (Fcb->Vcb->VcbCleanup == 0);
                                
                if (!PotentialVcbTeardown)  {

                    UDFReleaseUdfData(IrpContext);
                }
            }

            CurrentVcb = Fcb->Vcb;

            _Analysis_assume_(CurrentVcb != NULL);
            
            UDFAcquireVcbShared(IrpContext, CurrentVcb, FALSE);

            VcbHoldCount = 0;

        } else {

            VcbHoldCount += 1;
        }

        // Call our worker routine to perform the close operation.

        UDFCommonClosePrivate(IrpContext, CurrentVcb, Fcb, UserReference, FALSE);

        //  If the reference count on this Vcb is below our residual reference
        //  then check if we should dismount the volume.

        if (PotentialVcbTeardown) {

            UDFReleaseVcb( IrpContext, CurrentVcb );
            UDFCheckForDismount(IrpContext, CurrentVcb, FALSE);

            CurrentVcb = NULL;

            UDFReleaseUdfData(IrpContext);
            PotentialVcbTeardown = FALSE;
        }

        //  Complete the current request to cleanup the IrpContext.

        UDFCompleteRequest(IrpContext, NULL, STATUS_SUCCESS);
    }

    //  Release any Vcb we may still hold.

    if (CurrentVcb != NULL) {

        UDFReleaseVcb(IrpContext, CurrentVcb);

    }

#pragma prefast(suppress:26165, "Esp:1153")
    FsRtlExitFileSystem();
}

NTSTATUS
UDFBuildTreeItemsList(
    IN PVCB               Vcb,
    IN PUDF_FILE_INFO     FileInfo,
    IN PCHECK_TREE_ITEM   CheckItemProc,
    IN PUDF_FILE_INFO**   PassedList,
    IN PULONG             PassedListSize,
    IN PUDF_FILE_INFO**   FoundList,
    IN PULONG             FoundListSize
    )
{
    PDIR_INDEX_HDR     hDirNdx;
    PUDF_FILE_INFO     SDirInfo;
    ULONG              i;

    UDFPrint(("    UDFBuildTreeItemsList():\n"));
    if (!(*PassedList) || !(*FoundList)) {

        (*PassedList) = (PUDF_FILE_INFO*)
            MyAllocatePool__(NonPagedPool, sizeof(PUDF_FILE_INFO)*TREE_ITEM_LIST_GRAN);
        if (!(*PassedList))
            return STATUS_INSUFFICIENT_RESOURCES;
        (*PassedListSize) = 0;

        (*FoundList) = (PUDF_FILE_INFO*)
            MyAllocatePool__(NonPagedPool, sizeof(PUDF_FILE_INFO)*TREE_ITEM_LIST_GRAN);
        if (!(*FoundList)) {
            MyFreePool__(*PassedList);
            *PassedList = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        (*FoundListSize) = 0;
    }

    // check if already passed
    for(i=0;i<(*PassedListSize);i++) {
        if ( ((*PassedList)[i]) == FileInfo )
            return STATUS_SUCCESS;
    }
    // remember passed object
    // we should not proceed linked objects twice
    (*PassedListSize)++;
    if ( !((*PassedListSize) & (TREE_ITEM_LIST_GRAN - 1)) ) {
        if (!MyReallocPool__((PCHAR)(*PassedList), (*PassedListSize)*sizeof(PUDF_FILE_INFO),
                         (PCHAR*)PassedList, ((*PassedListSize)+TREE_ITEM_LIST_GRAN)*sizeof(PUDF_FILE_INFO))) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    (*PassedList)[(*PassedListSize)-1] = FileInfo;

    // check if this object matches our conditions
    if (CheckItemProc(FileInfo)) {
        // remember matched object
        (*FoundListSize)++;
        if ( !((*FoundListSize) & (TREE_ITEM_LIST_GRAN - 1)) ) {
            if (!MyReallocPool__((PCHAR)(*FoundList), (*FoundListSize)*sizeof(PUDF_DATALOC_INFO),
                             (PCHAR*)FoundList, ((*FoundListSize)+TREE_ITEM_LIST_GRAN)*sizeof(PUDF_DATALOC_INFO))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        (*FoundList)[(*FoundListSize)-1] = FileInfo;
    }

    // walk through SDir (if any)
    if ((SDirInfo = FileInfo->Dloc->SDirInfo))
        UDFBuildTreeItemsList(Vcb, SDirInfo, CheckItemProc,
                 PassedList, PassedListSize, FoundList, FoundListSize);

    // walk through subsequent objects (if any)
    if ((hDirNdx = FileInfo->Dloc->DirIndex)) {

        // scan DirIndex
        UDF_DIR_SCAN_CONTEXT ScanContext;
        PDIR_INDEX_ITEM DirNdx;
        PUDF_FILE_INFO CurFileInfo;

        if (UDFDirIndexInitScan(FileInfo, &ScanContext, 2)) {
            while((DirNdx = UDFDirIndexScan(&ScanContext, &CurFileInfo))) {
                if (!CurFileInfo)
                    continue;
                UDFBuildTreeItemsList(Vcb, CurFileInfo, CheckItemProc,
                         PassedList, PassedListSize, FoundList, FoundListSize);
            }
        }

    }
    return STATUS_SUCCESS;
} // end UDFBuildTreeItemsList()

BOOLEAN
UDFIsInDelayedCloseQueue(
    PUDF_FILE_INFO FileInfo)
{
    ASSERT(FileInfo);
    return (FileInfo->Fcb && FileInfo->Fcb->IrpContextLite);
} // end UDFIsInDelayedCloseQueue()

BOOLEAN
UDFIsLastClose(
    PUDF_FILE_INFO FileInfo)
{
    ASSERT(FileInfo);
    PFCB Fcb = FileInfo->Fcb;
    if ( Fcb &&
       !Fcb->FcbCleanup &&
        Fcb->FcbReference &&
        Fcb->FcbNonpaged->SegmentObject.DataSectionObject) {
        return TRUE;
    }
    return FALSE;
} // UDFIsLastClose()

NTSTATUS
UDFCloseAllXXXDelayedInDir(
    IN PVCB             Vcb,
    IN PUDF_FILE_INFO   FileInfo,
    IN BOOLEAN          System
    )
{
    PUDF_FILE_INFO*         PassedList = NULL;
    ULONG                   PassedListSize = 0;
    PUDF_FILE_INFO*         FoundList = NULL;
    ULONG                   FoundListSize = 0;
    NTSTATUS                RC;
    ULONG                   i;
    _SEH2_VOLATILE BOOLEAN  ResAcq = FALSE;
    _SEH2_VOLATILE BOOLEAN  AcquiredVcb = FALSE;
    PUDF_FILE_INFO          CurFileInfo;
    PFE_LIST_ENTRY          CurListPtr;
    PFE_LIST_ENTRY*         ListPtrArray = NULL;

    _SEH2_TRY {

        UDFPrint(("    UDFCloseAllXXXDelayedInDir(): Acquire DelayedCloseResource\n"));
        // Acquire DelayedCloseResource
        UDFAcquireResourceExclusive(&(UdfData.GlobalDataResource), TRUE);
        ResAcq = TRUE;

        UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE);
        AcquiredVcb = TRUE;

        RC = UDFBuildTreeItemsList(Vcb, FileInfo,
                System ? UDFIsLastClose : UDFIsInDelayedCloseQueue,
                &PassedList, &PassedListSize, &FoundList, &FoundListSize);

        if (!NT_SUCCESS(RC)) {
            UDFPrint(("    UDFBuildTreeItemsList(): error %x\n", RC));
            try_return(RC);
        }

        if (!FoundList || !FoundListSize) {
            try_return(RC = STATUS_SUCCESS);
        }

        // build array of referenced pointers
        ListPtrArray = (PFE_LIST_ENTRY*)(MyAllocatePool__(NonPagedPool, FoundListSize*sizeof(PFE_LIST_ENTRY)));
        if (!ListPtrArray) {
            UDFPrint(("    Can't alloc ListPtrArray for %x items\n", FoundListSize));
            try_return(RC = STATUS_INSUFFICIENT_RESOURCES);
        }

        for(i=0;i<FoundListSize;i++) {

            _SEH2_TRY {

                CurFileInfo = FoundList[i];
                if (!CurFileInfo->ListPtr) {
                    CurFileInfo->ListPtr = (PFE_LIST_ENTRY)(MyAllocatePool__(NonPagedPool, sizeof(FE_LIST_ENTRY)));
                    if (!CurFileInfo->ListPtr) {
                        UDFPrint(("    Can't alloc ListPtrEntry for items %x\n", i));
                        try_return(RC = STATUS_INSUFFICIENT_RESOURCES);
                    }
                    CurFileInfo->ListPtr->FileInfo = CurFileInfo;
                    CurFileInfo->ListPtr->EntryRefCount = 0;
                }
                CurFileInfo->ListPtr->EntryRefCount++;
                ListPtrArray[i] = CurFileInfo->ListPtr;

            } _SEH2_EXCEPT (EXCEPTION_EXECUTE_HANDLER) {
                BrutePoint();
            } _SEH2_END;
        }

        UDFReleaseResource(&(Vcb->VcbResource));
        AcquiredVcb = FALSE;

        if (System) {
            // Remove from system queue
            PFCB Fcb;
            IO_STATUS_BLOCK IoStatus;
            BOOLEAN NoDelayed = (Vcb->VcbState & UDF_VCB_FLAGS_NO_DELAYED_CLOSE) ?
                                     TRUE : FALSE;

            Vcb->VcbState |= UDF_VCB_FLAGS_NO_DELAYED_CLOSE;
            for(i=FoundListSize;i>0;i--) {
                UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE);
                AcquiredVcb = TRUE;
                _SEH2_TRY {

                    CurListPtr = ListPtrArray[i-1];
                    CurFileInfo = CurListPtr->FileInfo;
                    if (CurFileInfo &&
                       (Fcb = CurFileInfo->Fcb)) {
                        ASSERT((ULONG_PTR)Fcb > 0x1000);
//                            ASSERT((ULONG)(Fcb->SectionObject) > 0x1000);
                        if (!(Fcb->NtReqFCBFlags & UDF_NTREQ_FCB_DELETED) &&
                            (Fcb->NtReqFCBFlags & UDF_NTREQ_FCB_MODIFIED)) {
                            MmPrint(("    CcFlushCache()\n"));
                            CcFlushCache(&Fcb->FcbNonpaged->SegmentObject, NULL, 0, &IoStatus);
                        }
                        if (Fcb->FcbNonpaged->SegmentObject.ImageSectionObject) {
                            MmPrint(("    MmFlushImageSection()\n"));
                            MmFlushImageSection(&Fcb->FcbNonpaged->SegmentObject, MmFlushForWrite);
                        }
                        if (Fcb->FcbNonpaged->SegmentObject.DataSectionObject) {
                            MmPrint(("    CcPurgeCacheSection()\n"));
                            CcPurgeCacheSection(&Fcb->FcbNonpaged->SegmentObject, NULL, 0, FALSE);
                        }
                    } else {
                        MmPrint(("    Skip item: deleted\n"));
                    }
                    CurListPtr->EntryRefCount--;
                    if (!CurListPtr->EntryRefCount) {
                        if (CurListPtr->FileInfo)
                            CurListPtr->FileInfo->ListPtr = NULL;
                        MyFreePool__(CurListPtr);
                    }
                } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
                    BrutePoint();
                } _SEH2_END;
                UDFReleaseResource(&(Vcb->VcbResource));
                AcquiredVcb = FALSE;
            }
            if (!NoDelayed)
                Vcb->VcbState &= ~UDF_VCB_FLAGS_NO_DELAYED_CLOSE;
        } else {
            // Remove from internal queue
            PIRP_CONTEXT_LITE NextIrpContextLite;

            for(i=FoundListSize;i>0;i--) {

                UDFAcquireResourceExclusive(&(Vcb->VcbResource), TRUE);
                AcquiredVcb = TRUE;

                CurListPtr = ListPtrArray[i-1];
                CurFileInfo = CurListPtr->FileInfo;

                if (CurFileInfo &&
                   CurFileInfo->Fcb &&
                    (NextIrpContextLite = CurFileInfo->Fcb->IrpContextLite)) {

                    RemoveEntryList( &(NextIrpContextLite->DelayedCloseLinks) );

                    UdfData.DelayedCloseCount--;

                    UDFDoDelayedClose(NextIrpContextLite);
                }

                CurListPtr->EntryRefCount--;
                if (!CurListPtr->EntryRefCount) {
                    if (CurListPtr->FileInfo)
                        CurListPtr->FileInfo->ListPtr = NULL;
                    MyFreePool__(CurListPtr);
                }
                UDFReleaseResource(&(Vcb->VcbResource));
                AcquiredVcb = FALSE;
            }
        }
        RC = STATUS_SUCCESS;

try_exit: NOTHING;

    } _SEH2_FINALLY {
        // release Vcb
        if (AcquiredVcb)
            UDFReleaseResource(&(Vcb->VcbResource));
        // Release DelayedCloseResource
        if (ResAcq)
            UDFReleaseResource(&(UdfData.GlobalDataResource));

        if (ListPtrArray)
            MyFreePool__(ListPtrArray);
        if (PassedList)
            MyFreePool__(PassedList);
        if (FoundList)
            MyFreePool__(FoundList);
    } _SEH2_END;

    return RC;
} // end UDFCloseAllXXXDelayedInDir(


/*
    This routine adds request to Delayed Close queue.
    If number of queued requests exceeds higher threshold it fires
    UDFDelayedClose()
 */
NTSTATUS
UDFQueueClose(
    PIRP_CONTEXT IrpContext,
    PFCB Fcb,
    IN ULONG UserReference
    )
{
    PIRP_CONTEXT_LITE IrpContextLite;
    BOOLEAN                 StartWorker = FALSE;
    _SEH2_VOLATILE BOOLEAN  AcquiredVcb = FALSE;
    NTSTATUS                RC;

    AdPrint(("  UDFQueueDelayedClose\n"));

    _SEH2_TRY {
        // Acquire DelayedCloseResource
        UDFAcquireResourceExclusive(&(UdfData.GlobalDataResource), TRUE);

        UDFAcquireResourceShared(&Fcb->Vcb->VcbResource, TRUE);
        AcquiredVcb = TRUE;

        if (Fcb->FcbState & UDF_FCB_DELETE_ON_CLOSE) {
            try_return(RC = STATUS_DELETE_PENDING);
        }

        if (Fcb->IrpContextLite ||
           Fcb->FcbState & UDF_FCB_POSTED_RENAME) {
//            BrutePoint();
            try_return(RC = STATUS_UNSUCCESSFUL);
        }

        if (!NT_SUCCESS(RC = UDFInitializeIrpContextLite(&IrpContextLite,IrpContext,Fcb))) {
            try_return(RC);
        }

        IrpContextLite->UserReference = UserReference;

        InsertTailList(&UdfData.DelayedCloseQueue,
                       &IrpContextLite->DelayedCloseLinks);

        UdfData.DelayedCloseCount++;

        Fcb->IrpContextLite = IrpContextLite;

        //  If we are above our threshold then start the delayed
        //  close operation.
        if (UdfData.DelayedCloseCount > UdfData.MaxDelayedCloseCount) {

            UdfData.ReduceDelayedClose = TRUE;

            if (!UdfData.FspCloseActive) {

                UdfData.FspCloseActive = TRUE;
                StartWorker = TRUE;
            }
        }

        // Start the FspClose thread if we need to.
        if (StartWorker) {
            ExQueueWorkItem( &UdfData.CloseItem, CriticalWorkQueue );
        }
        RC = STATUS_SUCCESS;

try_exit:    NOTHING;

    } _SEH2_FINALLY {

        if (!NT_SUCCESS(RC)) {
            Fcb->FcbState &= ~UDF_FCB_DELAY_CLOSE;
        }
        if (AcquiredVcb) {
            UDFReleaseResource(&(Fcb->Vcb->VcbResource));
        }
        // Release DelayedCloseResource
        UDFReleaseResource(&(UdfData.GlobalDataResource));
    } _SEH2_END;
    return RC;
} // end UDFQueueDelayedClose()

