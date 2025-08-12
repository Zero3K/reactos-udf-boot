////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*************************************************************************
*
* File: protos.h
*
* Module: UDF File System Driver (Kernel mode execution only)
*
* Description:
*   Contains the prototypes for functions in UDF FSD.
*
*************************************************************************/

#ifndef _UDF_PROTOS_H_
#define _UDF_PROTOS_H_

#include "mem.h"

//  Type of opens.  FilObSup.c depends on this order.

typedef enum _TYPE_OF_OPEN {

    UnopenedFileObject = 0,
    StreamFileOpen,
    UserVolumeOpen,
    UserDirectoryOpen,
    UserFileOpen,
    BeyondValidType

} TYPE_OF_OPEN;

_When_(TypeOfOpen == UnopenedFileObject, _At_(Fcb, _In_opt_))
_When_(TypeOfOpen != UnopenedFileObject, _At_(Fcb, _In_))
VOID
UDFSetFileObject (
    _Inout_ PFILE_OBJECT FileObject,
    _In_ TYPE_OF_OPEN TypeOfOpen,
    PFCB Fcb,
    _In_opt_ PCCB Ccb
    );

_When_(return == UnopenedFileObject, _At_(*Fcb, _Post_null_))
_When_(return != UnopenedFileObject, _At_(Fcb, _Outptr_))
_When_(return == UnopenedFileObject, _At_(*Ccb, _Post_null_))
_When_(return != UnopenedFileObject, _At_(Ccb, _Outptr_))
TYPE_OF_OPEN
UDFDecodeFileObject (
    _In_ PFILE_OBJECT FileObject,
    PFCB *Fcb,
    PCCB *Ccb
    );

TYPE_OF_OPEN
UDFFastDecodeFileObject (
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFCB *Fcb
    );

PCCB
UDFDecodeFileObjectCcb(
    _In_ PFILE_OBJECT FileObject
    );


/*************************************************************************
* Prototypes for the file create.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFCreate(
    IN PDEVICE_OBJECT          DeviceObject,       // the logical volume device object
    IN PIRP                    Irp);               // I/O Request Packet

extern NTSTATUS UDFCommonCreate(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP                    Irp);

NTSTATUS
UDFFirstOpenFile(
    IN PIRP_CONTEXT IrpContext,
    IN PIO_STACK_LOCATION IrpSp,
    IN PVCB                    Vcb,                // volume control block
    IN PFILE_OBJECT            PtrNewFileObject,   // I/O Mgr. created file object
   OUT PFCB*                   PtrNewFcb,
    IN PUDF_FILE_INFO          RelatedFileInfo,
    IN PUDF_FILE_INFO          NewFileInfo,
    IN PUNICODE_STRING         LocalPath,
    IN PUNICODE_STRING         CurName
    );

NTSTATUS
UDFOpenFile(
    _In_ PIRP_CONTEXT IrpContext,
    _In_ PIO_STACK_LOCATION IrpSp,
    _In_ PVCB Vcb,
    _Inout_ PFCB *CurrentFcb,
    _In_ TYPE_OF_OPEN TypeOfOpen,
    _In_ ULONG UserCcbFlags
    );

NTSTATUS
UDFInitializeFCB(
    IN PFCB                    PtrNewFcb,          // FCB structure to be initialized
    IN PVCB                    Vcb,                // logical volume (VCB) pointer
    IN PtrUDFObjectName        PtrObjectName,      // name of the object
    IN ULONG                   Flags,              // is this a file/directory, etc.
    IN PFILE_OBJECT            FileObject          // optional file object to be initialized
    );

/*************************************************************************
* Prototypes for the file cleanup.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFCleanup(
PDEVICE_OBJECT              DeviceObject,       // the logical volume device object
PIRP                        Irp);               // I/O Request Packet

extern NTSTATUS UDFCommonCleanup(
PIRP_CONTEXT IrpContext,
PIRP                        Irp);

NTSTATUS
UDFCloseFileInfoChain(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb,
    IN PUDF_FILE_INFO fi,
    IN ULONG TreeLength,
    IN BOOLEAN VcbAcquired
    );

/*************************************************************************
* Prototypes for the file close.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFClose(
PDEVICE_OBJECT              DeviceObject,       // the logical volume device object
PIRP                        Irp);               // I/O Request Packet

NTSTATUS
UDFCommonClose(
    PIRP_CONTEXT IrpContext,
    PIRP Irp,
    BOOLEAN CanWait
    );

_Requires_lock_held_(_Global_critical_region_)
VOID
UDFTeardownStructures(
    _In_ PIRP_CONTEXT IrpContext,
    _Inout_ PFCB StartingFcb,
    _In_ ULONG TreeLength,
    _Out_ PBOOLEAN RemovedStartingFcb
    );

VOID
NTAPI
UDFFspClose(
    _In_opt_ PVCB Vcb
    );

extern NTSTATUS UDFCloseAllXXXDelayedInDir(IN PVCB           Vcb,
                                           IN PUDF_FILE_INFO FileInfo,
                                           IN BOOLEAN        System);

#define UDFCloseAllDelayedInDir(Vcb,FI) \
    UDFCloseAllXXXDelayedInDir(Vcb,FI,FALSE);

#define UDFCloseAllSystemDelayedInDir(Vcb,FI) \
    UDFCloseAllXXXDelayedInDir(Vcb,FI,TRUE);

NTSTATUS
UDFQueueClose(
    PIRP_CONTEXT IrpContext,
    PFCB Fcb,
    IN ULONG UserReference);

//extern VOID UDFRemoveFromDelayedQueue(PtrUDFFCB Fcb);
#define UDFRemoveFromDelayedQueue(Fcb) \
    UDFCloseAllDelayedInDir((Fcb)->Vcb, (Fcb)->FileInfo)

#define UDFRemoveFromSystemDelayedQueue(Fcb) \
    UDFCloseAllSystemDelayedInDir((Fcb)->Vcb, (Fcb)->FileInfo)

/*************************************************************************
* Prototypes for the file dircntrl.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFDirControl(
PDEVICE_OBJECT          DeviceObject,       // the logical volume device object
PIRP                    Irp);               // I/O Request Packet

extern NTSTATUS NTAPI UDFCommonDirControl(
PIRP_CONTEXT IrpContext,
PIRP                    Irp);

extern NTSTATUS NTAPI UDFQueryDirectory(
PIRP_CONTEXT IrpContext,
PIRP                    Irp,
PIO_STACK_LOCATION      IrpSp,
PFILE_OBJECT            FileObject,
PFCB                    Fcb,
PCCB                    Ccb);

extern NTSTATUS NTAPI UDFNotifyChangeDirectory(
PIRP_CONTEXT IrpContext,
PIRP                    Irp,
PIO_STACK_LOCATION      IrpSp,
PFILE_OBJECT            FileObject,
PFCB                    Fcb,
PCCB                    Ccb);

/*************************************************************************
* Prototypes for the file devcntrl.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFDeviceControl(
PDEVICE_OBJECT              DeviceObject,       // the logical volume device object
PIRP                        Irp);               // I/O Request Packet

NTSTATUS
UDFCommonDeviceControl(
    PIRP_CONTEXT IrpContext,
    PIRP Irp
    );

extern NTSTATUS NTAPI UDFDevIoctlCompletion(
PDEVICE_OBJECT              PtrDeviceObject,
PIRP                        Irp,
PVOID                       Context);

extern NTSTATUS NTAPI UDFHandleQueryPath(
PVOID                       BufferPointer);

/*************************************************************************
* Prototypes for the file fastio.cpp
*************************************************************************/
extern BOOLEAN NTAPI UDFFastIoCheckIfPossible(
IN PFILE_OBJECT             FileObject,
IN PLARGE_INTEGER           FileOffset,
IN ULONG                    Length,
IN BOOLEAN                  Wait,
IN ULONG                    LockKey,
IN BOOLEAN                  CheckForReadOperation,
OUT PIO_STATUS_BLOCK        IoStatus,
IN PDEVICE_OBJECT           DeviceObject);

extern FAST_IO_POSSIBLE NTAPI UDFIsFastIoPossible(
IN PFCB Fcb);

extern BOOLEAN NTAPI UDFFastIoQueryBasicInfo(
IN PFILE_OBJECT             FileObject,
IN BOOLEAN                  Wait,
OUT PFILE_BASIC_INFORMATION Buffer,
OUT PIO_STATUS_BLOCK        IoStatus,
IN PDEVICE_OBJECT           DeviceObject);

extern BOOLEAN NTAPI UDFFastIoQueryStdInfo(
IN PFILE_OBJECT                FileObject,
IN BOOLEAN                     Wait,
OUT PFILE_STANDARD_INFORMATION Buffer,
OUT PIO_STATUS_BLOCK           IoStatus,
IN PDEVICE_OBJECT              DeviceObject);

extern VOID NTAPI UDFFastIoRelCreateSec(
IN PFILE_OBJECT FileObject);

extern BOOLEAN NTAPI UDFAcqLazyWrite(
IN PVOID   Context,
IN BOOLEAN Wait);

extern VOID NTAPI UDFRelLazyWrite(
IN PVOID Context);

extern BOOLEAN NTAPI UDFAcqReadAhead(
IN PVOID   Context,
IN BOOLEAN Wait);

extern VOID NTAPI UDFRelReadAhead(
IN PVOID Context);

VOID NTAPI UDFDriverUnload(
    IN PDRIVER_OBJECT DriverObject);

extern BOOLEAN NTAPI UDFFastIoQueryNetInfo(
IN PFILE_OBJECT                                 FileObject,
IN BOOLEAN                                      Wait,
OUT struct _FILE_NETWORK_OPEN_INFORMATION*      Buffer,
OUT PIO_STATUS_BLOCK                            IoStatus,
IN PDEVICE_OBJECT                               DeviceObject);

extern BOOLEAN NTAPI UDFFastIoMdlRead(
IN PFILE_OBJECT             FileObject,
IN PLARGE_INTEGER           FileOffset,
IN ULONG                    Length,
IN ULONG                    LockKey,
OUT PMDL*                   MdlChain,
OUT PIO_STATUS_BLOCK        IoStatus,
IN PDEVICE_OBJECT           DeviceObject);

extern BOOLEAN UDFFastIoMdlReadComplete(
IN PFILE_OBJECT             FileObject,
OUT PMDL                    MdlChain,
IN PDEVICE_OBJECT           DeviceObject);

extern BOOLEAN NTAPI UDFFastIoPrepareMdlWrite(
IN PFILE_OBJECT             FileObject,
IN PLARGE_INTEGER           FileOffset,
IN ULONG                    Length,
IN ULONG                    LockKey,
OUT PMDL*                   MdlChain,
OUT PIO_STATUS_BLOCK        IoStatus,
IN PDEVICE_OBJECT           DeviceObject);

extern BOOLEAN NTAPI UDFFastIoMdlWriteComplete(
IN PFILE_OBJECT             FileObject,
IN PLARGE_INTEGER           FileOffset,
OUT PMDL                    MdlChain,
IN PDEVICE_OBJECT           DeviceObject);

extern NTSTATUS NTAPI UDFFastIoAcqModWrite(
IN PFILE_OBJECT             FileObject,
IN PLARGE_INTEGER           EndingOffset,
OUT PERESOURCE*             ResourceToRelease,
IN PDEVICE_OBJECT           DeviceObject);

extern NTSTATUS NTAPI UDFFastIoRelModWrite(
IN PFILE_OBJECT             FileObject,
IN PERESOURCE               ResourceToRelease,
IN PDEVICE_OBJECT           DeviceObject);

extern NTSTATUS NTAPI UDFFastIoAcqCcFlush(
IN PFILE_OBJECT             FileObject,
IN PDEVICE_OBJECT           DeviceObject);

extern NTSTATUS NTAPI UDFFastIoRelCcFlush(
IN PFILE_OBJECT             FileObject,
IN PDEVICE_OBJECT           DeviceObject);

/*************************************************************************
* Prototypes for the file fileinfo.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFQueryInfo(
PDEVICE_OBJECT  DeviceObject,       // the logical volume device object
PIRP            Irp);               // I/O Request Packet

extern NTSTATUS NTAPI UDFSetInfo(
PDEVICE_OBJECT  DeviceObject,       // the logical volume device object
PIRP            Irp);               // I/O Request Packet

extern NTSTATUS UDFCommonQueryInfo(
    PIRP_CONTEXT IrpContext,
    PIRP                    Irp);

extern NTSTATUS UDFCommonSetInfo(
PIRP_CONTEXT IrpContext,
PIRP                    Irp);

extern NTSTATUS UDFGetBasicInformation(
    IN PFILE_OBJECT                FileObject,
    IN PFCB                        Fcb,
    IN PFILE_BASIC_INFORMATION     PtrBuffer,
 IN OUT LONG*                      PtrReturnedLength);

extern NTSTATUS UDFGetNetworkInformation(
    IN PFCB                           Fcb,
    IN PFILE_NETWORK_OPEN_INFORMATION PtrBuffer,
 IN OUT PLONG                         PtrReturnedLength);

extern NTSTATUS UDFGetStandardInformation(
    IN PFCB                        Fcb,
    IN PFILE_STANDARD_INFORMATION  PtrBuffer,
 IN OUT PLONG                      PtrReturnedLength);

NTSTATUS
UDFGetInternalInformation(
    _In_ PIRP_CONTEXT IrpContext,
    _In_ PFCB Fcb,
    _Out_ PFILE_INTERNAL_INFORMATION Buffer,
    _Inout_ PLONG ReturnedLength
    );

extern NTSTATUS UDFGetEaInformation(
    PIRP_CONTEXT IrpContext,
    IN PFCB                 Fcb,
    IN PFILE_EA_INFORMATION PtrBuffer,
 IN OUT PLONG               PtrReturnedLength);

extern NTSTATUS UDFGetFullNameInformation(
    IN PFILE_OBJECT                FileObject,
    IN PFILE_NAME_INFORMATION      PtrBuffer,
 IN OUT PLONG                      PtrReturnedLength);

extern NTSTATUS UDFGetAltNameInformation(
    IN PFCB                        Fcb,
    IN PFILE_NAME_INFORMATION      PtrBuffer,
 IN OUT PLONG                      PtrReturnedLength);

extern NTSTATUS UDFGetPositionInformation(
    IN PFILE_OBJECT               FileObject,
    IN PFILE_POSITION_INFORMATION PtrBuffer,
 IN OUT PLONG                     PtrReturnedLength);

NTSTATUS
UDFGetFileStreamInformation(
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb,
    IN PFILE_STREAM_INFORMATION Buffer,
    IN OUT PULONG ReturnedLength
    );

extern NTSTATUS UDFSetBasicInformation(
    IN PFCB                   Fcb,
    IN PCCB                        Ccb,
    IN PFILE_OBJECT                FileObject,
    IN PFILE_BASIC_INFORMATION     PtrBuffer);

NTSTATUS
UDFMarkStreamsForDeletion(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB           Vcb,
    IN PFCB           Fcb,
    IN BOOLEAN        ForDel
    );

NTSTATUS
UDFSetDispositionInformation(
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb,
    IN PCCB Ccb,
    IN PVCB Vcb,
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Delete
    );

extern NTSTATUS UDFSetAllocationInformation(
    IN PFCB                            Fcb,
    IN PCCB                            Ccb,
    IN PVCB                            Vcb,
    IN PFILE_OBJECT                    FileObject,
    IN PIRP_CONTEXT IrpContext,
    IN PIRP                            Irp,
    IN PFILE_ALLOCATION_INFORMATION    PtrBuffer);

NTSTATUS UDFSetEOF(
    IN PIRP_CONTEXT IrpContext,
    IN PIO_STACK_LOCATION IrpSp,
    IN PFCB Fcb,
    IN PCCB Ccb,
    IN PVCB Vcb,
    IN PFILE_OBJECT FileObject,
    IN PIRP Irp,
    IN PFILE_END_OF_FILE_INFORMATION PtrBuffer
    );

NTSTATUS
UDFSetRenameInfo(
    IN PIRP_CONTEXT IrpContext,
    IN PIO_STACK_LOCATION IrpSp,
    IN PFCB Fcb,
    IN PCCB Ccb,
    IN PFILE_OBJECT FileObject,
    IN PFILE_RENAME_INFORMATION PtrBuffer
    );

NTSTATUS
UDFStoreFileId(
    IN PVCB Vcb,
    IN PCCB Ccb,
    IN PUDF_FILE_INFO fi,
    IN FILE_ID FileId
    );

NTSTATUS UDFRemoveFileId(
    IN PVCB Vcb,
    IN FILE_ID FileId
    );

#define UDFRemoveFileId__(Vcb, fi) \
    UDFRemoveFileId(Vcb, UDFGetNTFileId(Vcb, fi));

extern VOID UDFReleaseFileIdCache(
    IN PVCB Vcb);

NTSTATUS
UDFGetOpenParamsByFileId(
    IN PVCB Vcb,
    IN FILE_ID FileId,
    OUT PUNICODE_STRING* FName,
    OUT BOOLEAN* CaseSens
    );

NTSTATUS
UDFHardLink(
    IN PIRP_CONTEXT IrpContext,
    IN PIO_STACK_LOCATION IrpSp,
    IN PFCB Fcb1,
    IN PCCB Ccb1,
    IN PFILE_OBJECT FileObject1,   // Source File
    IN PFILE_LINK_INFORMATION PtrBuffer
    );

/*************************************************************************
* Prototypes for the file flush.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFFlushBuffers(
PDEVICE_OBJECT    DeviceObject,       // the logical volume device object
PIRP              Irp);               // I/O Request Packet

extern NTSTATUS UDFCommonFlush(
PIRP_CONTEXT IrpContext,
PIRP                        Irp);

ULONG UDFFlushAFile(
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb,
    IN PCCB Ccb,
    OUT PIO_STATUS_BLOCK PtrIoStatus,
    IN ULONG FlushFlags = 0
    );

ULONG
UDFFlushADirectory(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb,
    IN PUDF_FILE_INFO FI,
    OUT PIO_STATUS_BLOCK PtrIoStatus,
    ULONG FlushFlags = 0
    );

NTSTATUS
UDFFlushVolume(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    ULONG FlushFlags = 0
    );

extern NTSTATUS NTAPI UDFFlushCompletion(
PDEVICE_OBJECT              PtrDeviceObject,
PIRP                        Irp,
PVOID                       Context);

extern BOOLEAN UDFFlushIsBreaking(
IN PVCB         Vcb,
IN ULONG        FlushFlags = 0);

extern VOID UDFFlushTryBreak(
IN PVCB         Vcb);

/*************************************************************************
* Prototypes for the file fscntrl.cpp
*************************************************************************/

extern NTSTATUS NTAPI UDFFSControl(
PDEVICE_OBJECT      DeviceObject,
PIRP                Irp);

NTSTATUS
UDFCommonFSControl(
    PIRP_CONTEXT IrpContext,
    PIRP Irp
    );

extern NTSTATUS NTAPI UDFUserFsCtrlRequest(
PIRP_CONTEXT IrpContext,
PIRP                Irp);

extern NTSTATUS NTAPI UDFMountVolume(
PIRP_CONTEXT IrpContext,
PIRP Irp);

NTSTATUS
UDFUnlockVolumeInternal (
    IN PVCB Vcb,
    IN PFILE_OBJECT FileObject OPTIONAL
    );

extern VOID UDFScanForDismountedVcb (IN PIRP_CONTEXT IrpContext);

NTSTATUS
UDFCompleteMount(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb
    );

VOID
UDFCloseResidual(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb
    );

extern VOID     UDFCleanupVCB(IN PVCB Vcb);

extern NTSTATUS UDFIsVolumeMounted(IN PIRP_CONTEXT IrpContext,
                                   IN PIRP Irp);

extern NTSTATUS UDFIsVolumeDirty(IN PIRP_CONTEXT IrpContext,
                          IN PIRP Irp);

extern NTSTATUS UDFLockVolume (IN PIRP_CONTEXT IrpContext,
                               IN PIRP Irp);

extern NTSTATUS UDFUnlockVolume (IN PIRP_CONTEXT IrpContext,
                                 IN PIRP Irp);

_Requires_lock_held_(_Global_critical_region_)
_Requires_lock_held_(Vcb->VcbResource)
NTSTATUS
UDFLockVolumeInternal (
    _In_ PIRP_CONTEXT IrpContext,
    _Inout_ PVCB Vcb,
    _In_opt_ PFILE_OBJECT FileObject
    );

NTSTATUS
UDFIsPathnameValid(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    );

extern NTSTATUS UDFDismountVolume(IN PIRP_CONTEXT IrpContext,
                                  IN PIRP Irp);

extern NTSTATUS UDFGetVolumeBitmap(IN PIRP_CONTEXT IrpContext,
                                   IN PIRP Irp);

extern NTSTATUS UDFGetRetrievalPointers(IN PIRP_CONTEXT IrpContext,
                                        IN PIRP  Irp,
                                        IN ULONG Special);

extern NTSTATUS UDFInvalidateVolumes(IN PIRP_CONTEXT IrpContext,
                                     IN PIRP Irp);

/*************************************************************************
* Prototypes for the file LockCtrl.cpp
*************************************************************************/

extern NTSTATUS NTAPI UDFLockControl(
    IN PDEVICE_OBJECT DeviceObject,       // the logical volume device object
    IN PIRP           Irp);               // I/O Request Packet

extern NTSTATUS NTAPI UDFCommonLockControl(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP             Irp);

extern BOOLEAN NTAPI UDFFastLock(
    IN PFILE_OBJECT           FileObject,
    IN PLARGE_INTEGER         FileOffset,
    IN PLARGE_INTEGER         Length,
    PEPROCESS                 ProcessId,
    ULONG                     Key,
    BOOLEAN                   FailImmediately,
    BOOLEAN                   ExclusiveLock,
    OUT PIO_STATUS_BLOCK      IoStatus,
    IN PDEVICE_OBJECT         DeviceObject);

extern BOOLEAN NTAPI UDFFastUnlockSingle(
    IN PFILE_OBJECT           FileObject,
    IN PLARGE_INTEGER         FileOffset,
    IN PLARGE_INTEGER         Length,
    PEPROCESS                 ProcessId,
    ULONG                     Key,
    OUT PIO_STATUS_BLOCK      IoStatus,
    IN PDEVICE_OBJECT         DeviceObject);

extern BOOLEAN NTAPI UDFFastUnlockAll(
    IN PFILE_OBJECT           FileObject,
    PEPROCESS                 ProcessId,
    OUT PIO_STATUS_BLOCK      IoStatus,
    IN PDEVICE_OBJECT         DeviceObject);

BOOLEAN
NTAPI
UDFFastUnlockAllByKey(
    _In_ PFILE_OBJECT FileObject,
    _In_ PVOID ProcessId,
    _In_ ULONG Key,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ PDEVICE_OBJECT DeviceObject
    );

/*************************************************************************
* Prototypes for the file misc.cpp
*************************************************************************/
extern NTSTATUS UDFInitializeZones(
VOID);

extern VOID UDFDestroyZones(
VOID);

extern BOOLEAN __fastcall UDFIsIrpTopLevel(
PIRP                        Irp);                   // the IRP sent to our dispatch routine

extern long UDFExceptionFilter(
PIRP_CONTEXT IrpContext,
PEXCEPTION_POINTERS         PtrExceptionPointers);

extern NTSTATUS UDFProcessException(
PIRP_CONTEXT IrpContext,
PIRP                        Irp);

extern VOID UDFLogEvent(
NTSTATUS                    UDFEventLogId,  // the UDF private message id
NTSTATUS                    RC);            // any NT error code we wish to log ...

extern PtrUDFObjectName UDFAllocateObjectName(
VOID);

extern VOID UDFReleaseObjectName(
PtrUDFObjectName            PtrObjectName);

PCCB
UDFCreateCcb(
    );

extern VOID UDFReleaseCCB(PCCB Ccb);

extern
VOID
UDFDeleteCcb(
    PCCB Ccb
    );

PFCB
UDFCreateFcbOld(
    _In_ PIRP_CONTEXT IrpContext,
    _In_ FILE_ID FileId,
    _In_ NODE_TYPE_CODE NodeTypeCode,
    _Out_opt_ PBOOLEAN FcbExisted
    );

PFCB
UDFCreateFcb (
    _In_ PIRP_CONTEXT IrpContext,
    _In_ FILE_ID FileId,
    _In_ NODE_TYPE_CODE NodeTypeCode,
    _Out_opt_ PBOOLEAN FcbExisted
    );

VOID
UDFDeleteFcb(
    _In_ PIRP_CONTEXT IrpContext,
    _In_ PFCB Fcb
    );

VOID UDFCleanUpFCB(PFCB Fcb);

extern PIRP_CONTEXT UDFCreateIrpContext(
PIRP                        Irp,
PDEVICE_OBJECT              PtrTargetDeviceObject);

VOID
UDFCleanupIrpContext(
    _In_ PIRP_CONTEXT IrpContext,
    _In_ BOOLEAN Post = FALSE
    );

VOID
UDFCompleteRequest(
    _Inout_opt_ PIRP_CONTEXT IrpContext OPTIONAL,
    _Inout_opt_ PIRP Irp OPTIONAL,
    _In_ NTSTATUS Status
    );

extern NTSTATUS UDFPostRequest(
PIRP_CONTEXT IrpContext,
PIRP                        Irp);

VOID
NTAPI
UDFFspDispatch(
    PVOID Context
    );

NTSTATUS
UDFInitializeVCB(
    PIRP_CONTEXT IrpContext,
    PDEVICE_OBJECT VolumeDeviceObject,
    PDEVICE_OBJECT TargetDeviceObject,
    PVPB Vpb
    );

extern VOID
UDFReadRegKeys(
    PVCB Vcb,
    BOOLEAN Update,
    BOOLEAN UseCfg);

extern ULONG UDFGetRegParameter(
    IN PVCB Vcb,
    IN PCWSTR Name,
    IN ULONG DefValue = 0);

extern ULONG
UDFGetCfgParameter(
    IN PVCB Vcb,
    IN PCWSTR Name,
    IN ULONG DefValue
    );

extern VOID UDFDeleteVCB(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb);

extern ULONG UDFRegCheckParameterValue(
    IN PUNICODE_STRING RegistryPath,
    IN PCWSTR Name,
    IN PUNICODE_STRING PtrVolumePath,
    IN PCWSTR DefaultPath,
    IN ULONG DefValue = 0);

extern VOID UDFInitializeStackIrpContextFromLite(
    OUT PIRP_CONTEXT IrpContext,
    IN PIRP_CONTEXT_LITE IrpContextLite);

extern NTSTATUS UDFInitializeIrpContextLite (
    OUT PIRP_CONTEXT_LITE *IrpContextLite,
    IN PIRP_CONTEXT IrpContext,
    IN PFCB                Fcb);

extern ULONG
UDFIsResourceAcquired(
    IN PERESOURCE Resource
    );

extern BOOLEAN UDFAcquireResourceExclusiveWithCheck(
    IN PERESOURCE Resource
    );

extern BOOLEAN UDFAcquireResourceSharedWithCheck(
    IN PERESOURCE Resource
    );

extern NTSTATUS UDFWCacheErrorHandler(
    IN PVOID Context,
    IN PWCACHE_ERROR_CONTEXT ErrorInfo
    );

extern NTSTATUS NTAPI UDFFilterCallbackAcquireForCreateSection(
    IN PFS_FILTER_CALLBACK_DATA CallbackData,
    IN PVOID *CompletionContext
    );

_When_(RaiseOnError || return, _At_(Fcb->FileLock, _Post_notnull_))
_When_(RaiseOnError, _At_(IrpContext, _Pre_notnull_))
BOOLEAN
UDFCreateFileLock(
    _In_opt_ PIRP_CONTEXT IrpContext,
    _Inout_ PFCB Fcb,
    _In_ BOOLEAN RaiseOnError
);

/*************************************************************************
* Prototypes for the file NameSup.cpp
*************************************************************************/

#include "namesup.h"

/*************************************************************************
* Prototypes for the file Udf_info\physical.cpp
*************************************************************************/
#if 0

extern NTSTATUS UDFTRead(PVOID           _Vcb,
                         PVOID           Buffer,     // Target buffer
                         ULONG           Length,
                         ULONG           LBA,
                         PULONG          ReadBytes,
                         ULONG           Flags = 0);

extern NTSTATUS UDFTWrite(IN PVOID _Vcb,
                   IN PVOID Buffer,     // Target buffer
                   IN ULONG Length,
                   IN ULONG LBA,
                   OUT PULONG WrittenBytes,
                   IN ULONG Flags = 0);

extern NTSTATUS UDFPrepareForWriteOperation(
    IN PVCB Vcb,
    IN ULONG Lba,
    IN ULONG BCount);

extern NTSTATUS UDFReadDiscTrackInfo(PDEVICE_OBJECT DeviceObject, // the target device object
                                     PVCB           Vcb);         // Volume Control Block for ^ DevObj

extern NTSTATUS UDFUseStandard(PDEVICE_OBJECT DeviceObject, // the target device object
                               PVCB           Vcb);         // Volume control block fro this DevObj

extern NTSTATUS UDFGetBlockSize(PDEVICE_OBJECT DeviceObject, // the target device object
                                PVCB           Vcb);         // Volume control block fro this DevObj

extern NTSTATUS UDFGetDiskInfo(IN PDEVICE_OBJECT DeviceObject, // the target device object
                               IN PVCB           Vcb);         // Volume control block from this DevObj

extern VOID     UDFUpdateNWA(PVCB Vcb,
                             ULONG LBA,
                             ULONG BCount,
                             NTSTATUS RC);

extern NTSTATUS UDFDoDismountSequence(IN PVCB Vcb,
                                      IN BOOLEAN Eject);

// read physical sectors
NTSTATUS UDFReadSectors(IN PVCB Vcb,
                        IN BOOLEAN Translate,// Translate Logical to Physical
                        IN ULONG Lba,
                        IN ULONG BCount,
                        IN BOOLEAN Direct,
                        OUT PCHAR Buffer,
                        OUT PSIZE_T ReadBytes);

// read data inside physical sector
extern NTSTATUS UDFReadInSector(IN PVCB Vcb,
                         IN BOOLEAN Translate,       // Translate Logical to Physical
                         IN ULONG Lba,
                         IN ULONG i,                 // offset in sector
                         IN ULONG l,                 // transfer length
                         IN BOOLEAN Direct,
                         OUT PCHAR Buffer,
                         OUT PULONG ReadBytes);
// read unaligned data
extern NTSTATUS UDFReadData(IN PVCB Vcb,
                     IN BOOLEAN Translate,   // Translate Logical to Physical
                     IN LONGLONG Offset,
                     IN ULONG Length,
                     IN BOOLEAN Direct,
                     OUT PCHAR Buffer,
                     OUT PULONG ReadBytes);

// write physical sectors
NTSTATUS UDFWriteSectors(IN PVCB Vcb,
                         IN BOOLEAN Translate,      // Translate Logical to Physical
                         IN ULONG Lba,
                         IN ULONG WBCount,
                         IN BOOLEAN Direct,         // setting this flag delays flushing of given
                                                    // data to indefinite term
                         IN PCHAR Buffer,
                         OUT PULONG WrittenBytes);
// write directly to cached sector
NTSTATUS UDFWriteInSector(IN PVCB Vcb,
                          IN BOOLEAN Translate,       // Translate Logical to Physical
                          IN ULONG Lba,
                          IN ULONG i,                 // offset in sector
                          IN ULONG l,                 // transfer length
                          IN BOOLEAN Direct,
                          OUT PCHAR Buffer,
                          OUT PULONG WrittenBytes);
// write data at unaligned offset & length
NTSTATUS UDFWriteData(IN PVCB Vcb,
                      IN BOOLEAN Translate,      // Translate Logical to Physical
                      IN LONGLONG Offset,
                      IN ULONG Length,
                      IN BOOLEAN Direct,         // setting this flag delays flushing of given
                                                 // data to indefinite term
                      IN PCHAR Buffer,
                      OUT PULONG WrittenBytes);

NTSTATUS UDFResetDeviceDriver(IN PVCB Vcb.
                              IN PDEVICE_OBJECT TargetDeviceObject,
                              IN BOOLEAN Unlock);
#endif
/*************************************************************************
* Prototypes for the file Pnp.cpp
*************************************************************************/
NTSTATUS
NTAPI
UDFPnp (
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );

/*************************************************************************
* Prototypes for the file read.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFRead(
    PDEVICE_OBJECT              DeviceObject,       // the logical volume device object
    PIRP                        Irp);               // I/O Request Packet

extern NTSTATUS UDFPostStackOverflowRead(
    IN PIRP_CONTEXT IrpContext,
    IN PIRP             Irp,
    IN PFCB             Fcb);

extern VOID NTAPI UDFStackOverflowRead(
    IN PVOID Context,
    IN PKEVENT Event);

extern NTSTATUS UDFCommonRead(
    PIRP_CONTEXT IrpContext,
    PIRP             Irp);

extern PVOID UDFMapUserBuffer(
    PIRP Irp);

NTSTATUS
UDFLockUserBuffer(
    PIRP_CONTEXT IrpContext,
    ULONG BufferLength,
    LOCK_OPERATION LockOperation
    );

extern NTSTATUS UDFUnlockCallersBuffer(
    PIRP_CONTEXT IrpContext,
    PIRP    Irp,
    PVOID   SystemBuffer);

NTSTATUS
UDFCompleteMdl(
    PIRP_CONTEXT IrpContext,
    PIRP Irp
    );

extern NTSTATUS
UDFCheckAccessRights(
    PFILE_OBJECT FileObject,
    PACCESS_STATE AccessState,
    PFCB         Fcb,
    PCCB         Ccb,
    ACCESS_MASK  DesiredAccess,
    USHORT       ShareAccess);

extern NTSTATUS
UDFSetAccessRights(
    PFILE_OBJECT FileObject,
    PACCESS_STATE AccessState,
    PFCB         Fcb,
    PCCB         Ccb,
    ACCESS_MASK  DesiredAccess,
    USHORT       ShareAccess);

/*************************************************************************
* Prototypes for the file Shutdown.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFShutdown(
PDEVICE_OBJECT              DeviceObject,       // the logical volume device object
PIRP                        Irp);               // I/O Request Packet

NTSTATUS
UDFCommonShutdown(
    _Inout_ PIRP_CONTEXT IrpContext,
    _Inout_ PIRP Irp
    );

/*************************************************************************
* Prototypes for the file Udf_dbg.cpp
*************************************************************************/
extern BOOLEAN
UDFDebugAcquireResourceSharedLite(
      IN PERESOURCE Resource,
      IN BOOLEAN    Wait,
      ULONG         BugCheckId,
      ULONG         Line);

extern BOOLEAN
UDFDebugAcquireSharedStarveExclusive(
      IN PERESOURCE Resource,
      IN BOOLEAN    Wait,
      ULONG         BugCheckId,
      ULONG         Line);

extern BOOLEAN
UDFDebugAcquireResourceExclusiveLite(
      IN PERESOURCE Resource,
      IN BOOLEAN    Wait,
      ULONG         BugCheckId,
      ULONG         Line);

extern VOID
UDFDebugReleaseResourceForThreadLite(
    IN PERESOURCE  Resource,
    IN ERESOURCE_THREAD  ResourceThreadId,
    ULONG         BugCheckId,
    ULONG         Line);

extern VOID
UDFDebugDeleteResource(
    IN PERESOURCE  Resource,
    IN ERESOURCE_THREAD  ResourceThreadId,
    ULONG         BugCheckId,
    ULONG         Line);

extern NTSTATUS
UDFDebugInitializeResourceLite(
    IN PERESOURCE  Resource,
    IN ERESOURCE_THREAD  ResourceThreadId,
    ULONG         BugCheckId,
    ULONG         Line);

extern VOID
UDFDebugConvertExclusiveToSharedLite(
    IN PERESOURCE  Resource,
    IN ERESOURCE_THREAD  ResourceThreadId,
    ULONG         BugCheckId,
    ULONG         Line);

extern BOOLEAN
UDFDebugAcquireSharedWaitForExclusive(
    IN PERESOURCE Resource,
    IN BOOLEAN    Wait,
    ULONG         BugCheckId,
    ULONG         Line);

extern LONG
UDFDebugInterlockedIncrement(
    IN PLONG      addr,
    ULONG         BugCheckId,
    ULONG         Line);

extern LONG
UDFDebugInterlockedDecrement(
    IN PLONG      addr,
    ULONG         BugCheckId,
    ULONG         Line);

extern LONG
UDFDebugInterlockedExchangeAdd(
    IN PLONG      addr,
    IN LONG       i,
    ULONG         BugCheckId,
    ULONG         Line);

/*************************************************************************
* Prototypes for the file UDFinit.cpp
*************************************************************************/
extern "C" NTSTATUS NTAPI DriverEntry(
PDRIVER_OBJECT              DriverObject,       // created by the I/O sub-system
PUNICODE_STRING             RegistryPath);      // path to the registry key

extern VOID NTAPI UDFInitializeFunctionPointers(
PDRIVER_OBJECT              DriverObject);      // created by the I/O sub-system

extern VOID NTAPI
UDFFsNotification(IN PDEVICE_OBJECT DeviceObject,
                  IN BOOLEAN FsActive);

#ifndef WIN64
//extern ptrFsRtlNotifyVolumeEvent FsRtlNotifyVolumeEvent;
#endif //WIN64

extern BOOLEAN
UDFGetInstallVersion(PULONG iVer);

extern BOOLEAN
UDFGetInstallTime(PULONG iTime);

extern BOOLEAN
UDFGetTrialEnd(PULONG iTrial);

/*************************************************************************
* Prototypes for the file verify.cpp
*************************************************************************/

extern NTSTATUS UDFVerifyVcb (
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb
    );

NTSTATUS
UDFVerifyFcbOperation(
    IN PIRP_CONTEXT IrpContext OPTIONAL,
    IN PFCB Fcb,
    IN PCCB Ccb
);

NTSTATUS UDFVerifyVolume (
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp
    );

extern NTSTATUS UDFPerformVerify (
    IN PIRP_CONTEXT IrpContext,
    IN PIRP Irp,
    IN PDEVICE_OBJECT DeviceToVerify
    );

extern BOOLEAN UDFCheckForDismount (
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb,
    IN BOOLEAN VcbAcquired
    );

BOOLEAN
UDFDismountVcb (
    IN PIRP_CONTEXT IrpContext,
    IN PVCB Vcb,
    IN BOOLEAN VcbAcquired
    );

NTSTATUS
UDFCompareVcb(
    IN PIRP_CONTEXT IrpContext,
    IN PVCB OldVcb,
    IN PVCB NewVcb,
    IN BOOLEAN PhysicalOnly
    );

/*************************************************************************
* Prototypes for the file VolInfo.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFQueryVolInfo(PDEVICE_OBJECT DeviceObject,
                                      PIRP Irp);

extern NTSTATUS UDFCommonQueryVolInfo (PIRP_CONTEXT IrpContext,
                                       PIRP Irp);

extern NTSTATUS NTAPI UDFSetVolInfo(PDEVICE_OBJECT DeviceObject,       // the logical volume device object
                              PIRP           Irp);               // I/O Request Packet

extern NTSTATUS UDFCommonSetVolInfo(PIRP_CONTEXT IrpContext,
                                    PIRP             Irp);

/*************************************************************************
* Prototypes for the file write.cpp
*************************************************************************/
extern NTSTATUS NTAPI UDFWrite(
PDEVICE_OBJECT              DeviceObject,       // the logical volume device object
PIRP                        Irp);               // I/O Request Packet

extern NTSTATUS UDFCommonWrite(
PIRP_CONTEXT IrpContext,
PIRP                        Irp);

extern VOID NTAPI UDFDeferredWriteCallBack (
VOID                        *Context1,          // Should be IrpContext
VOID                        *Context2);         // Should be Irp

extern VOID UDFPurgeCacheEx_(
PFCB                        Fcb,
LONGLONG                    Offset,
LONGLONG                    Length,
//#ifndef ALLOW_SPARSE
BOOLEAN                     CanWait,
//#endif ALLOW_SPARSE
PVCB                        Vcb,
PFILE_OBJECT                FileObject
);

extern VOID UDFSetModified(
    IN PVCB        Vcb
);

extern VOID UDFPreClrModified(
    IN PVCB        Vcb
);

extern VOID UDFClrModified(
    IN PVCB        Vcb
);

/*#ifdef ALLOW_SPARSE
  #define UDFZeroDataEx(Fcb, Offset, Length, CanWait) \
      UDFPurgeCacheEx_(Fcb, Offset, Length)
  #define UDFPurgeCacheEx(Fcb, Offset, Length, CanWait) \
      UDFPurgeCacheEx_(Fcb, Offset, Length)
#else // ALLOW_SPARSE*/
  #define UDFZeroDataEx(Fcb, Offset, Length, CanWait, Vcb, FileObject) \
      UDFPurgeCacheEx_(Fcb, Offset, Length, CanWait, Vcb, FileObject)
  #define UDFPurgeCacheEx(Fcb, Offset, Length, CanWait, Vcb, FileObject) \
      UDFPurgeCacheEx_(Fcb, Offset, Length, CanWait, Vcb, FileObject)
//#endif //ALLOW_SPARSE

BOOLEAN
UDFZeroData (
    IN PVCB Vcb,
    IN PFILE_OBJECT FileObject,
    IN ULONG StartingZero,
    IN ULONG ByteCount,
    IN BOOLEAN CanWait
    );

NTSTATUS
UDFToggleMediaEjectDisable (
    IN PVCB Vcb,
    IN BOOLEAN PreventRemoval
    );

NTSTATUS
UDFHijackIrpAndFlushDevice (
    _In_ PIRP_CONTEXT IrpContext,
    _Inout_ PIRP Irp,
    _In_ PDEVICE_OBJECT TargetDeviceObject
    );

BOOLEAN
UDFMarkDevForVerifyIfVcbMounted(
    IN PVCB Vcb
    );

//
//  BOOLEAN
//  UdfDeviceIsFsdo(
//      IN PDEVICE_OBJECT D
//      );
//
//  Evaluates to TRUE if the supplied device object is one of the file system devices
//  we created at initialisation.
//

#define UdfDeviceIsFsdo(D)  (((D) == UdfData.UDFDeviceObject_CD) || ((D) == UdfData.UDFDeviceObject_HDD))

//
//  The following macro is used by the dispatch routines to determine if
//  an operation is to be done with or without Write Through.
//
//      BOOLEAN
//      IsFileWriteThrough (
//          IN PFILE_OBJECT FileObject,
//          IN PVCB Vcb
//          );
//

#define IsFileWriteThrough(FO,VCB) (             \
    BooleanFlagOn((FO)->Flags, FO_WRITE_THROUGH) \
)

#define AssertVerifyDeviceIrp(I)                                                    \
    NT_ASSERT( (I) == NULL ||                                                       \
            !(((I)->IoStatus.Status) == STATUS_VERIFY_REQUIRED &&                   \
              ((I)->Tail.Overlay.Thread == NULL ||                                  \
                IoGetDeviceToVerify( (I)->Tail.Overlay.Thread ) == NULL )));

//  Macros to abstract device verify flag changes.

#define UDFUpdateMediaChangeCount( V, C)  (V)->MediaChangeCount = (C)
#define UDFUpdateVcbCondition( V, C)      (V)->VcbCondition = (C)

#define UDFMarkRealDevForVerify( DO)  SetFlag( (DO)->Flags, DO_VERIFY_VOLUME)
                                     
#define UDFMarkRealDevVerifyOk( DO)   ClearFlag( (DO)->Flags, DO_VERIFY_VOLUME)

#define UDFRealDevNeedsVerify( DO)    BooleanFlagOn( (DO)->Flags, DO_VERIFY_VOLUME)

#define UDFLockVcb(IC,V)                                                                \
    ASSERT(KeAreApcsDisabled());                                                        \
    ExAcquireFastMutexUnsafe( &(V)->VcbMutex );                                         \
    (V)->VcbLockThread = PsGetCurrentThread()

#define UDFUnlockVcb(IC,V)                                                              \
    (V)->VcbLockThread = NULL;                                                          \
    ExReleaseFastMutexUnsafe( &(V)->VcbMutex )

#define UDFIncrementCleanupCounts(IC,F) {        \
    ASSERT_LOCKED_VCB( (F)->Vcb );              \
    (F)->FcbCleanup += 1;                       \
    (F)->Vcb->VcbCleanup += 1;                  \
}

#define UDFDecrementCleanupCounts(IC,F) {        \
    ASSERT_LOCKED_VCB( (F)->Vcb );              \
    (F)->FcbCleanup -= 1;                       \
    (F)->Vcb->VcbCleanup -= 1;                  \
}

#define UDFIncrementReferenceCounts(IC,F,C,UC) { \
    ASSERT_LOCKED_VCB( (F)->Vcb );              \
    (F)->FcbReference += (C);                   \
    (F)->FcbUserReference += (UC);              \
    (F)->Vcb->VcbReference += (C);              \
    (F)->Vcb->VcbUserReference += (UC);         \
}

#define UDFDecrementReferenceCounts(IC,F,C,UC) { \
    ASSERT_LOCKED_VCB( (F)->Vcb );              \
    (F)->FcbReference -= (C);                   \
    (F)->FcbUserReference -= (UC);              \
    (F)->Vcb->VcbReference -= (C);              \
    (F)->Vcb->VcbUserReference -= (UC);         \
}

#define UDFLockUdfData()                                                                \
    ASSERT(KeAreApcsDisabled());                                                        \
    ExAcquireFastMutexUnsafe(&UdfData.UdfDataMutex);                                    \
    UdfData.UdfDataLockThread = PsGetCurrentThread()

#define UDFUnlockUdfData()                                                              \
    UdfData.UdfDataLockThread = NULL;                                                   \
    ExReleaseFastMutexUnsafe(&UdfData.UdfDataMutex)

enum TYPE_OF_ACQUIRE {
    
    AcquireExclusive,
    AcquireShared,
    AcquireSharedStarveExclusive

};

_Requires_lock_held_(_Global_critical_region_)
_When_(Type == AcquireExclusive && return != FALSE, _Acquires_exclusive_lock_(*Resource))
_When_(Type == AcquireShared && return != FALSE, _Acquires_shared_lock_(*Resource))
_When_(Type == AcquireSharedStarveExclusive && return != FALSE, _Acquires_shared_lock_(*Resource))
_When_(IgnoreWait == FALSE, _Post_satisfies_(return == TRUE))
BOOLEAN
UDFAcquireResource(
    _In_ PIRP_CONTEXT IrpContext,
    _Inout_ PERESOURCE Resource,
    _In_ BOOLEAN IgnoreWait,
    _In_ TYPE_OF_ACQUIRE Type
    );

#define UDFAcquireVcbExclusive(IC,V,I)                                                  \
    UDFAcquireResource( (IC), &(V)->VcbResource, (I), AcquireExclusive )

#define UDFAcquireVcbShared(IC,V,I)                                                     \
    UDFAcquireResource((IC), &(V)->VcbResource, (I), AcquireShared)

#define UDFReleaseVcb(IC,V)                                                             \
    ExReleaseResourceLite(&(V)->VcbResource)

#define UDFAcquireUdfData(IC)                                                           \
    ExAcquireResourceExclusiveLite(&UdfData.GlobalDataResource, TRUE)

#define UDFReleaseUdfData(IC)                                                           \
    ExReleaseResourceLite(&UdfData.GlobalDataResource)

#define UDFAcquireFcbExclusive(IC,F,I)                                                  \
    UDFAcquireResource((IC), &(F)->FcbNonpaged->FcbResource, (I), AcquireExclusive)

#define UDFAcquireFcbShared(IC,F,I)                                                     \
    UDFAcquireResource((IC), &(F)->FcbNonpaged->FcbResource, (I), AcquireShared)

#define UDFReleaseFcb(IC,F)                                                             \
    ExReleaseResourceLite(&(F)->FcbNonpaged->FcbResource)

VOID
UDFSetThreadContext(
    _Inout_ PIRP_CONTEXT IrpContext,
    _In_ PTHREAD_CONTEXT ThreadContext
    );

#endif  // _UDF_PROTOS_H_
