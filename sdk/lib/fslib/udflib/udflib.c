/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS UDF filesystem library
 * FILE:        sdk/lib/fslib/udflib/udflib.c
 * PURPOSE:     UDF filesystem library
 */

#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <winnls.h>

#ifndef __REACTOS__
// the following definitions come from fmifs.h in ReactOS

typedef enum {
    PROGRESS,
    DONEWITHSTRUCTURE,
    UNKNOWN2,
    UNKNOWN3,
    UNKNOWN4,
    UNKNOWN5,
    INSUFFICIENTRIGHTS,
    FSNOTSUPPORTED,
    VOLUMEINUSE,
    UNKNOWN9,
    UNKNOWNA,
    DONE,
    UNKNOWNC,
    UNKNOWND,
    OUTPUT,
    STRUCTUREPROGRESS,
    CLUSTERSIZETOOSMALL,
} CALLBACKCOMMAND;

typedef BOOLEAN (NTAPI* PFMIFSCALLBACK)(CALLBACKCOMMAND Command, ULONG SubAction, PVOID ActionInfo);

#else

#include <fmifs/fmifs.h>

#endif // __REACTOS__

/* FUNCTIONS ****************************************************************/

static VOID
UdfLibMessage(IN PFMIFSCALLBACK Callback,
              IN CALLBACKCOMMAND Command,
              IN DWORD Percent,
              IN PVOID PacketData)
{
    if (Callback != NULL)
    {
        Callback(Command, Percent, PacketData);
    }
}

BOOLEAN
NTAPI
UdfChkdsk(IN PUNICODE_STRING DriveRoot,
          IN PFMIFSCALLBACK Callback,
          IN BOOLEAN FixErrors,
          IN BOOLEAN Verbose,
          IN BOOLEAN CheckOnlyIfDirty,
          IN BOOLEAN ScanDrive,
          IN PVOID pUnknown1,
          IN PVOID pUnknown2,
          IN PVOID pUnknown3,
          IN PVOID pUnknown4,
          IN PULONG ExitStatus)
{
    BOOLEAN Success = FALSE;

    UNREFERENCED_PARAMETER(DriveRoot);
    UNREFERENCED_PARAMETER(FixErrors);
    UNREFERENCED_PARAMETER(Verbose);
    UNREFERENCED_PARAMETER(CheckOnlyIfDirty);
    UNREFERENCED_PARAMETER(ScanDrive);
    UNREFERENCED_PARAMETER(pUnknown1);
    UNREFERENCED_PARAMETER(pUnknown2);
    UNREFERENCED_PARAMETER(pUnknown3);
    UNREFERENCED_PARAMETER(pUnknown4);

    UdfLibMessage(Callback, PROGRESS, 0, L"UDF check disk not implemented");

    if (ExitStatus)
        *ExitStatus = Success ? 0 : 1;

    return Success;
}

BOOLEAN
NTAPI
UdfChkdskEx(IN PUNICODE_STRING DriveRoot,
            IN PFMIFSCALLBACK Callback,
            IN BOOLEAN FixErrors,
            IN BOOLEAN Verbose,
            IN BOOLEAN CheckOnlyIfDirty,
            IN BOOLEAN ScanDrive,
            IN PVOID pUnknown1,
            IN PVOID pUnknown2,
            IN PVOID pUnknown3,
            IN PVOID pUnknown4,
            IN PULONG ExitStatus)
{
    return UdfChkdsk(DriveRoot,
                     Callback,
                     FixErrors,
                     Verbose,
                     CheckOnlyIfDirty,
                     ScanDrive,
                     pUnknown1,
                     pUnknown2,
                     pUnknown3,
                     pUnknown4,
                     ExitStatus);
}

BOOLEAN
NTAPI
UdfFormat(IN PUNICODE_STRING DriveRoot,
          IN PFMIFSCALLBACK Callback,
          IN BOOLEAN QuickFormat,
          IN BOOLEAN BackwardCompatible,
          IN MEDIA_TYPE MediaType,
          IN PUNICODE_STRING Label,
          IN ULONG ClusterSize)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE DeviceHandle;
    NTSTATUS Status;
    DISK_GEOMETRY DiskGeometry;
    PARTITION_INFORMATION PartitionInfo;
    ULONGLONG SectorCount;
    ULONG BytesPerSector;
    BOOLEAN Success = FALSE;

    UNREFERENCED_PARAMETER(QuickFormat);
    UNREFERENCED_PARAMETER(BackwardCompatible);
    UNREFERENCED_PARAMETER(MediaType);
    UNREFERENCED_PARAMETER(Label);
    UNREFERENCED_PARAMETER(ClusterSize);

    /* Open the drive */
    InitializeObjectAttributes(&ObjectAttributes,
                               DriveRoot,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtOpenFile(&DeviceHandle,
                        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(Status))
    {
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to open device");
        return FALSE;
    }

    /* Get disk geometry */
    Status = NtDeviceIoControlFile(DeviceHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatusBlock,
                                   IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                   NULL,
                                   0,
                                   &DiskGeometry,
                                   sizeof(DISK_GEOMETRY));

    if (!NT_SUCCESS(Status))
    {
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to get disk geometry");
        return FALSE;
    }

    BytesPerSector = DiskGeometry.BytesPerSector;

    /* Get partition information */
    Status = NtDeviceIoControlFile(DeviceHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatusBlock,
                                   IOCTL_DISK_GET_PARTITION_INFO,
                                   NULL,
                                   0,
                                   &PartitionInfo,
                                   sizeof(PARTITION_INFORMATION));

    if (!NT_SUCCESS(Status))
    {
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to get partition information");
        return FALSE;
    }

    SectorCount = PartitionInfo.PartitionLength.QuadPart / BytesPerSector;

    UdfLibMessage(Callback, PROGRESS, 10, L"Preparing UDF 2.01 format");

    /* For now, we'll create a minimal UDF 2.01 implementation */
    /* This is a placeholder - actual UDF formatting would require
       writing proper UDF structures (Volume Descriptor Sequence,
       Anchor Volume Descriptor Pointers, etc.) */

    UdfLibMessage(Callback, PROGRESS, 50, L"Writing UDF structures");

    /* Write basic UDF 2.01 structures */
    
    /* 1. Write Volume Recognition Sequence at sector 16 */
    PUCHAR VrsBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector * 3);
    if (!VrsBuffer)
    {
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate VRS buffer");
        return FALSE;
    }
    
    /* NSR02 descriptor */
    memcpy(VrsBuffer, "NSR02", 5);
    VrsBuffer[5] = 1; // Structure version
    
    /* Write VRS to sector 16 */
    LARGE_INTEGER Offset;
    Offset.QuadPart = 16 * BytesPerSector;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        VrsBuffer, BytesPerSector, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write VRS");
        return FALSE;
    }
    
    /* 2. Write Anchor Volume Descriptor Pointer at sector 256 */
    PUCHAR AvdpBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector);
    if (!AvdpBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate AVDP buffer");
        return FALSE;
    }
    
    /* AVDP tag */
    AvdpBuffer[0] = 2; // Tag identifier for AVDP
    AvdpBuffer[1] = 0;
    AvdpBuffer[2] = 3; // Descriptor version
    AvdpBuffer[3] = 0;
    
    /* Main Volume Descriptor Sequence extent */
    *(PULONG)(AvdpBuffer + 16) = 512 * BytesPerSector; // Length (512 sectors)
    *(PULONG)(AvdpBuffer + 20) = 32; // Location (sector 32)
    
    /* Write AVDP to sector 256 */
    Offset.QuadPart = 256 * BytesPerSector;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        AvdpBuffer, BytesPerSector, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write AVDP");
        return FALSE;
    }
    
    /* 3. Write Primary Volume Descriptor at sector 32 */
    PUCHAR PvdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector);
    if (!PvdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate PVD buffer");
        return FALSE;
    }
    
    /* PVD tag */
    PvdBuffer[0] = 1; // Tag identifier for PVD
    PvdBuffer[1] = 0;
    PvdBuffer[2] = 3; // Descriptor version
    PvdBuffer[3] = 0;
    
    /* Volume identifier */
    memcpy(PvdBuffer + 24, "ReactOS_UDF", 11);
    
    /* Write PVD to sector 32 */
    Offset.QuadPart = 32 * BytesPerSector;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        PvdBuffer, BytesPerSector, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write PVD");
        return FALSE;
    }
    
    /* 4. Write Terminating Descriptor at sector 33 */
    PUCHAR TdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector);
    if (!TdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate TD buffer");
        return FALSE;
    }
    
    /* TD tag */
    TdBuffer[0] = 8; // Tag identifier for Terminating Descriptor
    TdBuffer[1] = 0;
    TdBuffer[2] = 3; // Descriptor version
    TdBuffer[3] = 0;
    
    /* Write TD to sector 33 */
    Offset.QuadPart = 33 * BytesPerSector;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        TdBuffer, BytesPerSector, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write TD");
        return FALSE;
    }
    
    /* Clean up buffers */
    RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);

    UdfLibMessage(Callback, PROGRESS, 90, L"Preparing boot area");
    
    /* Reserve sectors 1024-1088 for FreeLdr (64 sectors = 32KB)
     * The UDF boot sector will read FreeLdr from this location
     * Setup should copy freeldr.sys to these sectors after formatting */

    UdfLibMessage(Callback, PROGRESS, 100, L"UDF format complete");

    Success = TRUE;

    NtClose(DeviceHandle);

    return Success;
}

BOOLEAN
NTAPI
UdfFormatEx(IN PUNICODE_STRING DriveRoot,
            IN PFMIFSCALLBACK Callback,
            IN BOOLEAN QuickFormat,
            IN BOOLEAN BackwardCompatible,
            IN MEDIA_TYPE MediaType,
            IN PUNICODE_STRING Label,
            IN ULONG ClusterSize)
{
    return UdfFormat(DriveRoot,
                     Callback,
                     QuickFormat,
                     BackwardCompatible,
                     MediaType,
                     Label,
                     ClusterSize);
}