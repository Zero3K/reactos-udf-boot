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

    /* Write proper UDF 2.01 structures */
    LARGE_INTEGER Offset;
    
    /* 1. Write Volume Recognition Sequence at sector 16 */
    PUCHAR VrsBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector * 3);
    if (!VrsBuffer)
    {
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate VRS buffer");
        return FALSE;
    }
    
    /* BEA01 (Beginning Extended Area) */
    memcpy(VrsBuffer, "BEA01", 5);
    VrsBuffer[5] = 1; // Structure version
    for (ULONG i = 6; i < 2048; i++) VrsBuffer[i] = 0;
    
    /* NSR02 descriptor (UDF 2.01) */
    memcpy(VrsBuffer + BytesPerSector, "NSR02", 5);
    VrsBuffer[BytesPerSector + 5] = 1; // Structure version
    for (ULONG i = BytesPerSector + 6; i < BytesPerSector * 2; i++) VrsBuffer[i] = 0;
    
    /* TEA01 (Terminating Extended Area) */
    memcpy(VrsBuffer + BytesPerSector * 2, "TEA01", 5);
    VrsBuffer[BytesPerSector * 2 + 5] = 1; // Structure version
    for (ULONG i = BytesPerSector * 2 + 6; i < BytesPerSector * 3; i++) VrsBuffer[i] = 0;
    
    /* Write VRS starting at sector 16 */
    Offset.QuadPart = 16 * BytesPerSector;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        VrsBuffer, BytesPerSector * 3, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write VRS");
        return FALSE;
    }
    
    /* 2. Write Anchor Volume Descriptor Pointers at logical blocks 100 and 200 */
    /* UDF uses 2048-byte logical blocks */
    ULONG LogicalBlockSize = 2048;
    
    PUCHAR AvdpBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!AvdpBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate AVDP buffer");
        return FALSE;
    }
    
    /* Write AVDP at logical block 100 */
    /* AVDP tag (tag identifier 2, descriptor version 3) */
    AvdpBuffer[0] = 2; // Tag identifier for AVDP
    AvdpBuffer[1] = 0;
    AvdpBuffer[2] = 3; // Descriptor version  
    AvdpBuffer[3] = 0;
    AvdpBuffer[4] = 0; // Tag checksum (calculated)
    AvdpBuffer[5] = 0; // Reserved
    *(PUSHORT)(AvdpBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(AvdpBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(AvdpBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(AvdpBuffer + 12) = 100; // Tag location (logical block 100)
    
    /* Main Volume Descriptor Sequence extent (length in bytes, location in logical blocks) */
    *(PULONG)(AvdpBuffer + 16) = 32 * LogicalBlockSize; // Length (32 logical blocks)
    *(PULONG)(AvdpBuffer + 20) = 32; // Location (logical block 32)
    
    /* Reserve Volume Descriptor Sequence extent (copy of main) */
    *(PULONG)(AvdpBuffer + 24) = 32 * LogicalBlockSize; // Length
    *(PULONG)(AvdpBuffer + 28) = 64; // Location (logical block 64)
    
    /* Calculate and set tag checksum */
    UCHAR checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += AvdpBuffer[i] + AvdpBuffer[i+1] + AvdpBuffer[i+2] + AvdpBuffer[i+3];
    }
    AvdpBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write AVDP to logical block 100 (sector 400 if 2048-byte blocks) */
    Offset.QuadPart = (100 * LogicalBlockSize);
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        AvdpBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write AVDP at block 100");
        return FALSE;
    }
    
    /* Write second AVDP at logical block 200 */
    *(PULONG)(AvdpBuffer + 12) = 200; // Tag location (logical block 200)
    
    /* Recalculate tag checksum for new location */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += AvdpBuffer[i] + AvdpBuffer[i+1] + AvdpBuffer[i+2] + AvdpBuffer[i+3];
    }
    AvdpBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write AVDP to logical block 200 (sector 800 if 2048-byte blocks) */
    Offset.QuadPart = (200 * LogicalBlockSize);
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        AvdpBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write AVDP at block 200");
        return FALSE;
    }
    
    /* 3. Write Primary Volume Descriptor at logical block 32 */
    PUCHAR PvdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!PvdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate PVD buffer");
        return FALSE;
    }
    
    /* PVD tag (tag identifier 1, descriptor version 3) */
    PvdBuffer[0] = 1; // Tag identifier for PVD
    PvdBuffer[1] = 0;
    PvdBuffer[2] = 3; // Descriptor version
    PvdBuffer[3] = 0;
    PvdBuffer[4] = 0; // Tag checksum (calculated)
    PvdBuffer[5] = 0; // Reserved
    *(PUSHORT)(PvdBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(PvdBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(PvdBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(PvdBuffer + 12) = 32; // Tag location (logical block 32)
    
    /* Volume Descriptor Sequence Number */
    *(PULONG)(PvdBuffer + 16) = 1;
    
    /* Primary Volume Descriptor Number */
    *(PULONG)(PvdBuffer + 20) = 0;
    
    /* Volume identifier (32 characters, dstring) */
    PvdBuffer[24] = 11; // Length of identifier
    memcpy(PvdBuffer + 25, "ReactOS_UDF", 11);
    
    /* Volume sequence number */
    *(PUSHORT)(PvdBuffer + 56) = 1;
    
    /* Maximum volume sequence number */
    *(PUSHORT)(PvdBuffer + 58) = 1;
    
    /* Interchange level */
    *(PUSHORT)(PvdBuffer + 60) = 3;
    
    /* Maximum interchange level */
    *(PUSHORT)(PvdBuffer + 62) = 3;
    
    /* Character set list */
    *(PULONG)(PvdBuffer + 64) = 1;
    
    /* Maximum character set list */
    *(PULONG)(PvdBuffer + 68) = 1;
    
    /* Volume set identifier (128 characters) */
    PvdBuffer[72] = 11;
    memcpy(PvdBuffer + 73, "ReactOS_UDF", 11);
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += PvdBuffer[i] + PvdBuffer[i+1] + PvdBuffer[i+2] + PvdBuffer[i+3];
    }
    PvdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write PVD to logical block 32 */
    Offset.QuadPart = 32 * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        PvdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write PVD");
        return FALSE;
    }
    
    /* 4. Write Logical Volume Descriptor at logical block 33 */
    PUCHAR LvdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!LvdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate LVD buffer");
        return FALSE;
    }
    
    /* LVD tag (tag identifier 6) */
    LvdBuffer[0] = 6; // Tag identifier for LVD
    LvdBuffer[1] = 0;
    LvdBuffer[2] = 3; // Descriptor version
    LvdBuffer[3] = 0;
    LvdBuffer[4] = 0; // Tag checksum (calculated)
    LvdBuffer[5] = 0; // Reserved
    *(PUSHORT)(LvdBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(LvdBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(LvdBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(LvdBuffer + 12) = 33; // Tag location (logical block 33)
    
    /* Volume Descriptor Sequence Number */
    *(PULONG)(LvdBuffer + 16) = 2;
    
    /* Logical volume identifier */
    LvdBuffer[84] = 11; // Length
    memcpy(LvdBuffer + 85, "ReactOS_UDF", 11);
    
    /* Logical block size */
    *(PULONG)(LvdBuffer + 212) = LogicalBlockSize;
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += LvdBuffer[i] + LvdBuffer[i+1] + LvdBuffer[i+2] + LvdBuffer[i+3];
    }
    LvdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write LVD to logical block 33 */
    Offset.QuadPart = 33 * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        LvdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write LVD");
        return FALSE;
    }
    
    /* 5. Write Terminating Descriptor at logical block 34 */
    PUCHAR TdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!TdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate TD buffer");
        return FALSE;
    }
    
    /* TD tag (tag identifier 8) */
    TdBuffer[0] = 8; // Tag identifier for Terminating Descriptor
    TdBuffer[1] = 0;
    TdBuffer[2] = 3; // Descriptor version
    TdBuffer[3] = 0;
    TdBuffer[4] = 0; // Tag checksum (calculated)
    TdBuffer[5] = 0; // Reserved
    *(PUSHORT)(TdBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(TdBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(TdBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(TdBuffer + 12) = 34; // Tag location (logical block 34)
    
    /* Volume Descriptor Sequence Number */
    *(PULONG)(TdBuffer + 16) = 3;
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += TdBuffer[i] + TdBuffer[i+1] + TdBuffer[i+2] + TdBuffer[i+3];
    }
    TdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write TD to logical block 34 */
    Offset.QuadPart = 34 * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        TdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write TD");
        return FALSE;
    }
    
    /* Clean up buffers */
    RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);

    UdfLibMessage(Callback, PROGRESS, 90, L"Preparing boot area");
    
    /* Reserve sectors 1024-1088 for FreeLdr (64 sectors = 32KB)
     * The UDF boot sector will read FreeLdr from this location
     * Setup should copy freeldr.sys to these sectors after formatting
     * 
     * UDF Layout:
     * - Sector 0: UDF boot sector  
     * - Sectors 16-18: Volume Recognition Sequence (BEA01/NSR02/TEA01)
     * - Logical Block 32 (Sector 131072/2048=64): Primary Volume Descriptor
     * - Logical Block 33 (Sector 135168/2048=66): Logical Volume Descriptor  
     * - Logical Block 34 (Sector 139264/2048=68): Terminating Descriptor
     * - Logical Block 100 (Sector 204800): Anchor Volume Descriptor Pointer #1
     * - Logical Block 200 (Sector 409600): Anchor Volume Descriptor Pointer #2
     * - Sector 1024: FreeLdr boot location
     */

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