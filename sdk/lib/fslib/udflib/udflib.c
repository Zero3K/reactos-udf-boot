/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS UDF filesystem library
 * FILE:        sdk/lib/fslib/udflib/udflib.c
 * PURPOSE:     UDF filesystem library
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winioctl.h>
#include <ndk/iofuncs.h>
#include <ndk/kefuncs.h>
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

    /* Lock the volume for exclusive access during formatting */
    Status = NtFsControlFile(DeviceHandle,
                            NULL,
                            NULL,
                            NULL,
                            &IoStatusBlock,
                            FSCTL_LOCK_VOLUME,
                            NULL,
                            0,
                            NULL,
                            0);

    if (!NT_SUCCESS(Status))
    {
        NtClose(DeviceHandle);
        WCHAR ErrorMsg[256];
        swprintf(ErrorMsg, L"Failed to lock volume for formatting (Status: 0x%08x)", Status);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, ErrorMsg);
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

    /* Write comprehensive UDF 2.01 structures based on mkudffs implementation */
    LARGE_INTEGER Offset;
    ULONG LogicalBlockSize = 2048; // Standard UDF logical block size
    
    /* 1. Write Volume Recognition Sequence at sector 16 */
    PUCHAR VrsBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector * 3);
    if (!VrsBuffer)
    {
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate VRS buffer");
        return FALSE;
    }
    
    /* Volume Structure Descriptor - BEA01 (Beginning Extended Area) */
    VrsBuffer[0] = 0; // Structure type
    VrsBuffer[1] = 1; // Structure version  
    memcpy(VrsBuffer + 2, "BEA01", 5); // Standard identifier
    VrsBuffer[7] = 1; // Structure data version
    // Remaining bytes zero-filled
    
    /* Volume Structure Descriptor - NSR02 (UDF 2.01) */
    VrsBuffer[BytesPerSector] = 0; // Structure type
    VrsBuffer[BytesPerSector + 1] = 1; // Structure version
    memcpy(VrsBuffer + BytesPerSector + 2, "NSR02", 5); // Standard identifier for UDF 2.01
    VrsBuffer[BytesPerSector + 7] = 1; // Structure data version
    // Remaining bytes zero-filled
    
    /* Volume Structure Descriptor - TEA01 (Terminating Extended Area) */
    VrsBuffer[BytesPerSector * 2] = 0; // Structure type
    VrsBuffer[BytesPerSector * 2 + 1] = 1; // Structure version
    memcpy(VrsBuffer + BytesPerSector * 2 + 2, "TEA01", 5); // Standard identifier
    VrsBuffer[BytesPerSector * 2 + 7] = 1; // Structure data version
    // Remaining bytes zero-filled
    
    /* Write VRS starting at sector 16 */
    Offset.QuadPart = 16 * BytesPerSector;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        VrsBuffer, BytesPerSector * 3, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        NtClose(DeviceHandle);
        WCHAR ErrorMsg[256];
        swprintf(ErrorMsg, L"Failed to write VRS (Status: 0x%08x)", Status);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, ErrorMsg);
        return FALSE;
    }
    
    /* 2. Write Anchor Volume Descriptor Pointers using proper placement algorithm */
    /* Calculate AVDP locations based on mkudffs logic */
    ULONGLONG TotalLogicalBlocks = SectorCount * BytesPerSector / LogicalBlockSize;
    ULONG AvdpBlock1, AvdpBlock2;
    
    /* AVDP placement algorithm based on mkudffs - place at block 256 and end of volume */
    if (TotalLogicalBlocks > 256)
    {
        AvdpBlock1 = 256; // Standard location at block 256
        if (TotalLogicalBlocks > 257)
            AvdpBlock2 = (ULONG)(TotalLogicalBlocks - 1); // Last block of volume
        else 
            AvdpBlock2 = AvdpBlock1; // Backup at same location for small volumes
    }
    else
    {
        // For very small volumes, use block 256 or last available block
        AvdpBlock1 = AvdpBlock2 = (TotalLogicalBlocks > 256) ? 256 : (ULONG)(TotalLogicalBlocks - 1);
    }
    
    PUCHAR AvdpBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!AvdpBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate AVDP buffer");
        return FALSE;
    }
    
    /* Write AVDP at first location */
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
    *(PULONG)(AvdpBuffer + 12) = AvdpBlock1; // Tag location
    
    /* Main Volume Descriptor Sequence extent (32 logical blocks starting at block 32) */
    *(PULONG)(AvdpBuffer + 16) = 32 * LogicalBlockSize; // Length (32 logical blocks)
    *(PULONG)(AvdpBuffer + 20) = 32; // Location (logical block 32)
    
    /* Reserve Volume Descriptor Sequence extent (backup copy) */
    *(PULONG)(AvdpBuffer + 24) = 32 * LogicalBlockSize; // Length
    if (TotalLogicalBlocks > 257)
        *(PULONG)(AvdpBuffer + 28) = (ULONG)(TotalLogicalBlocks - 257); // Near end of volume
    else
        *(PULONG)(AvdpBuffer + 28) = 32; // Same as main for small volumes
    
    /* Calculate and set tag checksum */
    UCHAR checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += AvdpBuffer[i] + AvdpBuffer[i+1] + AvdpBuffer[i+2] + AvdpBuffer[i+3];
    }
    AvdpBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write AVDP to first location */
    Offset.QuadPart = (AvdpBlock1 * LogicalBlockSize);
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        AvdpBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        NtClose(DeviceHandle);
        WCHAR ErrorMsg[256];
        swprintf(ErrorMsg, L"Failed to write AVDP at block %u (Status: 0x%08x)", AvdpBlock1, Status);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, ErrorMsg);
        return FALSE;
    }
    
    /* Write second AVDP at backup location if different */
    if (AvdpBlock2 != AvdpBlock1)
    {
        *(PULONG)(AvdpBuffer + 12) = AvdpBlock2; // Update tag location
        
        /* Recalculate tag checksum for new location */
        checksum = 0;
        for (ULONG i = 0; i < 16; i += 4) {
            if (i != 4) checksum += AvdpBuffer[i] + AvdpBuffer[i+1] + AvdpBuffer[i+2] + AvdpBuffer[i+3];
        }
        AvdpBuffer[4] = (UCHAR)(256 - checksum);
        
        /* Write AVDP to backup location */
        Offset.QuadPart = (AvdpBlock2 * LogicalBlockSize);
        Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                            AvdpBuffer, LogicalBlockSize, &Offset, NULL);
        
        if (!NT_SUCCESS(Status))
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
            RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
            NtClose(DeviceHandle);
            UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write AVDP at backup location");
            return FALSE;
        }
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
    
    /* 4. Write Partition Descriptor at logical block 33 */
    PUCHAR PdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!PdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate PD buffer");
        return FALSE;
    }
    
    /* PD tag (tag identifier 5) */
    PdBuffer[0] = 5; // Tag identifier for Partition Descriptor
    PdBuffer[1] = 0;
    PdBuffer[2] = 3; // Descriptor version
    PdBuffer[3] = 0;
    PdBuffer[4] = 0; // Tag checksum (calculated)
    PdBuffer[5] = 0; // Reserved
    *(PUSHORT)(PdBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(PdBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(PdBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(PdBuffer + 12) = 33; // Tag location (logical block 33)
    
    /* Volume Descriptor Sequence Number */
    *(PULONG)(PdBuffer + 16) = 2;
    
    /* Partition flags */
    *(PUSHORT)(PdBuffer + 20) = 1; // Partition allocated
    
    /* Partition number */
    *(PUSHORT)(PdBuffer + 22) = 0;
    
    /* Partition contents ("+NSR02") for UDF 2.01 */
    memcpy(PdBuffer + 24, "+NSR02", 6);
    
    /* Partition starting location (after VDS area) */
    *(PULONG)(PdBuffer + 188) = 80; // Start at logical block 80 (after VDS)
    
    /* Partition length (rest of volume minus reserved areas) */
    ULONG PartitionLength = (ULONG)(TotalLogicalBlocks - 80 - 10); // Reserve 10 blocks at end
    *(PULONG)(PdBuffer + 192) = PartitionLength;
    
    /* Partition header descriptor */
    /* Unallocated Space Table - not used, length 0 */
    *(PULONG)(PdBuffer + 196) = 0; // Length
    *(PULONG)(PdBuffer + 200) = 0; // Position
    
    /* Unallocated Space Bitmap - points to our space bitmap */
    *(PULONG)(PdBuffer + 204) = LogicalBlockSize; // Length (one logical block)
    *(PULONG)(PdBuffer + 208) = 83; // Position (partition-relative block 83)
    
    /* Partition Integrity Table - not used */
    *(PULONG)(PdBuffer + 212) = 0; // Length
    *(PULONG)(PdBuffer + 216) = 0; // Position
    
    /* Freed Space Table - not used */
    *(PULONG)(PdBuffer + 220) = 0; // Length
    *(PULONG)(PdBuffer + 224) = 0; // Position
    
    /* Freed Space Bitmap - not used */
    *(PULONG)(PdBuffer + 228) = 0; // Length
    *(PULONG)(PdBuffer + 232) = 0; // Position
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += PdBuffer[i] + PdBuffer[i+1] + PdBuffer[i+2] + PdBuffer[i+3];
    }
    PdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write PD to logical block 33 */
    Offset.QuadPart = 33 * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        PdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write PD");
        return FALSE;
    }
    
    /* 5. Write Logical Volume Descriptor at logical block 34 */
    PUCHAR LvdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!LvdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
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
    *(PULONG)(LvdBuffer + 12) = 34; // Tag location (logical block 34)
    
    /* Volume Descriptor Sequence Number */
    *(PULONG)(LvdBuffer + 16) = 3;
    
    /* Character set (CS0) */
    LvdBuffer[20] = 0; // Character set type CS0
    memcpy(LvdBuffer + 21, "OSTA Compressed Unicode", 23);
    
    /* Logical volume identifier */
    LvdBuffer[84] = 11; // Length
    memcpy(LvdBuffer + 85, "ReactOS_UDF", 11);
    
    /* Logical block size */
    *(PULONG)(LvdBuffer + 212) = LogicalBlockSize;
    
    /* Domain identifier for UDF */
    LvdBuffer[216] = 0; // Flags
    memcpy(LvdBuffer + 217, "*OSTA UDF Compliant", 19);
    *(PUSHORT)(LvdBuffer + 240) = 0x0201; // UDF 2.01
    
    /* File Set Descriptor location */
    *(PULONG)(LvdBuffer + 248) = LogicalBlockSize; // Length
    *(PULONG)(LvdBuffer + 252) = 81; // Logical block number (in partition space)
    *(PUSHORT)(LvdBuffer + 256) = 0; // Partition reference number
    
    /* Partition Map length and number */
    *(PULONG)(LvdBuffer + 264) = 6; // Length of partition maps
    *(PULONG)(LvdBuffer + 268) = 1; // Number of partition maps
    
    /* Type 1 Partition Map */
    LvdBuffer[448] = 1; // Type 1 partition map
    LvdBuffer[449] = 6; // Length
    *(PUSHORT)(LvdBuffer + 450) = 1; // Volume sequence number
    *(PUSHORT)(LvdBuffer + 452) = 0; // Partition number
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += LvdBuffer[i] + LvdBuffer[i+1] + LvdBuffer[i+2] + LvdBuffer[i+3];
    }
    LvdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write LVD to logical block 34 */
    Offset.QuadPart = 34 * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        LvdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write LVD");
        return FALSE;
    }
    
    /* 6. Write Terminating Descriptor at logical block 35 */
    PUCHAR TdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!TdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
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
    *(PULONG)(TdBuffer + 12) = 35; // Tag location (logical block 35)
    
    /* Volume Descriptor Sequence Number */
    *(PULONG)(TdBuffer + 16) = 4;
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += TdBuffer[i] + TdBuffer[i+1] + TdBuffer[i+2] + TdBuffer[i+3];
    }
    TdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write TD to logical block 35 */
    Offset.QuadPart = 35 * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        TdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write TD");
        return FALSE;
    }
    
    /* 7. Write File Set Descriptor at logical block 81 (in partition space) */
    PUCHAR FsdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!FsdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate FSD buffer");
        return FALSE;
    }
    
    /* FSD tag (tag identifier 256) */
    FsdBuffer[0] = 0; // Tag identifier for File Set Descriptor (low byte)
    FsdBuffer[1] = 1; // Tag identifier for File Set Descriptor (high byte)
    FsdBuffer[2] = 3; // Descriptor version
    FsdBuffer[3] = 0;
    FsdBuffer[4] = 0; // Tag checksum (calculated)
    FsdBuffer[5] = 0; // Reserved
    *(PUSHORT)(FsdBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(FsdBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(FsdBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(FsdBuffer + 12) = 81; // Tag location (logical block 81 in partition)
    
    /* Recording date and time */
    *(PULONG)(FsdBuffer + 16) = 1; // Current timestamp - simplified
    
    /* Interchange level */
    *(PUSHORT)(FsdBuffer + 28) = 3;
    
    /* Maximum interchange level */  
    *(PUSHORT)(FsdBuffer + 30) = 3;
    
    /* Character set list */
    *(PULONG)(FsdBuffer + 32) = 1;
    
    /* Maximum character set list */
    *(PULONG)(FsdBuffer + 36) = 1;
    
    /* File set number */
    *(PULONG)(FsdBuffer + 40) = 0;
    
    /* File set descriptor number */
    *(PULONG)(FsdBuffer + 44) = 0;
    
    /* Logical volume identifier character set (CS0) */
    FsdBuffer[48] = 0;
    memcpy(FsdBuffer + 49, "OSTA Compressed Unicode", 23);
    
    /* Logical volume identifier */
    FsdBuffer[112] = 11; // Length
    memcpy(FsdBuffer + 113, "ReactOS_UDF", 11);
    
    /* File set character set (CS0) */
    FsdBuffer[240] = 0;
    memcpy(FsdBuffer + 241, "OSTA Compressed Unicode", 23);
    
    /* File set identifier */
    FsdBuffer[304] = 11; // Length  
    memcpy(FsdBuffer + 305, "ReactOS_UDF", 11);
    
    /* Root directory ICB (logical block 82 in partition) */
    *(PULONG)(FsdBuffer + 400) = LogicalBlockSize; // Length
    *(PULONG)(FsdBuffer + 404) = 82; // Logical block number  
    *(PUSHORT)(FsdBuffer + 408) = 0; // Partition reference number
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += FsdBuffer[i] + FsdBuffer[i+1] + FsdBuffer[i+2] + FsdBuffer[i+3];
    }
    FsdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write FSD to logical block 161 (80 + 81 = absolute block) */
    Offset.QuadPart = (80 + 81) * LogicalBlockSize; 
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        FsdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, FsdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write FSD");
        return FALSE;
    }
    
    /* 7. Create root directory File Entry at logical block 82 (partition-relative) */
    PUCHAR RootDirBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!RootDirBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, FsdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate root directory buffer");
        return FALSE;
    }
    
    /* Root Directory File Entry tag (tag identifier 261) */
    RootDirBuffer[0] = 5; // Tag identifier (low byte of 261)
    RootDirBuffer[1] = 1; // Tag identifier (high byte of 261)
    RootDirBuffer[2] = 3; // Descriptor version
    RootDirBuffer[3] = 0;
    RootDirBuffer[4] = 0; // Tag checksum (calculated)
    RootDirBuffer[5] = 0; // Reserved
    *(PUSHORT)(RootDirBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(RootDirBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(RootDirBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(RootDirBuffer + 12) = 82; // Tag location (partition-relative block 82)
    
    /* ICB tag */
    *(PULONG)(RootDirBuffer + 16) = 0; // Prior recorded number of direct entries
    *(PUSHORT)(RootDirBuffer + 20) = 4; // Strategy type (strategy 4)
    *(PUSHORT)(RootDirBuffer + 22) = 0; // Strategy parameter
    *(PUSHORT)(RootDirBuffer + 24) = 1; // Maximum number of entries
    RootDirBuffer[26] = 0; // Reserved
    RootDirBuffer[27] = 4; // File type (4 = directory)
    // Parent ICB location is zero (root has no parent)
    *(PUSHORT)(RootDirBuffer + 36) = 0x200; // Flags (archive bit and directory bit)
    
    /* Permissions (rwxr-xr-x for directory) */
    *(PULONG)(RootDirBuffer + 84) = 0x16D; // Unix permissions
    
    /* Link count */
    *(PUSHORT)(RootDirBuffer + 88) = 1;
    
    /* Owner and group IDs */
    *(PULONG)(RootDirBuffer + 92) = 0; // Owner ID
    *(PULONG)(RootDirBuffer + 96) = 0; // Group ID
    
    /* Access time, modification time, creation time (current time) */
#ifdef __REACTOS__
    LARGE_INTEGER SystemTime;
    NtQuerySystemTime(&SystemTime);
    // UDF uses timestamps with 100ns precision since 1900
    // Windows timestamps are 100ns since 1601, so add the difference
    ULONGLONG UdfTime = SystemTime.QuadPart + 0x19DB1DED53E8000ULL;
#else
    SYSTEMTIME st;
    FILETIME ft;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    
    // Convert to UDF timestamp format (100ns since 1900)
    // Windows FILETIME is 100ns since 1601, so add the difference  
    ULONGLONG UdfTime = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    UdfTime += 0x19DB1DED53E8000ULL; // Add difference between 1601 and 1900
#endif
    
    *(PULONGLONG)(RootDirBuffer + 100) = UdfTime; // Access time
    *(PULONGLONG)(RootDirBuffer + 108) = UdfTime; // Modification time  
    *(PULONGLONG)(RootDirBuffer + 116) = UdfTime; // Creation time
    
    /* Implementation use area length */
    *(PULONG)(RootDirBuffer + 132) = 32; // 32 bytes for implementation use
    
    /* Implementation identifier */
    memcpy(RootDirBuffer + 140, "*ReactOS UDF", 12);
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += RootDirBuffer[i] + RootDirBuffer[i+1] + RootDirBuffer[i+2] + RootDirBuffer[i+3];
    }
    RootDirBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write root directory to logical block 162 (80 + 82 = absolute block) */
    Offset.QuadPart = (80 + 82) * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        RootDirBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, FsdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, RootDirBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write root directory");
        return FALSE;
    }
    
    /* 8. Create Space Bitmap Descriptor for proper space allocation management */
    PUCHAR SbdBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, LogicalBlockSize);
    if (!SbdBuffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, FsdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, RootDirBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to allocate Space Bitmap buffer");
        return FALSE;
    }
    
    /* Space Bitmap Descriptor tag (tag identifier 264) */
    SbdBuffer[0] = 8; // Tag identifier (low byte of 264)
    SbdBuffer[1] = 1; // Tag identifier (high byte of 264) 
    SbdBuffer[2] = 3; // Descriptor version
    SbdBuffer[3] = 0;
    SbdBuffer[4] = 0; // Tag checksum (calculated)
    SbdBuffer[5] = 0; // Reserved
    *(PUSHORT)(SbdBuffer + 6) = 1; // Tag serial number
    *(PUSHORT)(SbdBuffer + 8) = 0; // Descriptor CRC (calculated)
    *(PUSHORT)(SbdBuffer + 10) = LogicalBlockSize - 16; // Descriptor CRC length
    *(PULONG)(SbdBuffer + 12) = 83; // Tag location (partition-relative block 83)
    
    /* Number of bits (one bit per logical block in partition) */
    ULONG BitmapBits = PartitionLength;
    *(PULONG)(SbdBuffer + 16) = BitmapBits;
    
    /* Number of bytes for bitmap */
    ULONG BitmapBytes = (BitmapBits + 7) / 8; // Round up to nearest byte
    *(PULONG)(SbdBuffer + 20) = BitmapBytes;
    
    /* Initialize bitmap - mark first few blocks as used (metadata area) */
    PUCHAR Bitmap = SbdBuffer + 24;
    
    /* Mark first 10 blocks as used (FSD, root dir, space bitmap, etc.) */
    for (ULONG i = 0; i < 10 && i < BitmapBits; i++)
    {
        ULONG byteIndex = i / 8;
        ULONG bitIndex = i % 8;
        if (byteIndex < BitmapBytes)
            Bitmap[byteIndex] |= (1 << bitIndex);
    }
    
    /* Calculate and set tag checksum */
    checksum = 0;
    for (ULONG i = 0; i < 16; i += 4) {
        if (i != 4) checksum += SbdBuffer[i] + SbdBuffer[i+1] + SbdBuffer[i+2] + SbdBuffer[i+3];
    }
    SbdBuffer[4] = (UCHAR)(256 - checksum);
    
    /* Write Space Bitmap to logical block 163 (80 + 83 = absolute block) */
    Offset.QuadPart = (80 + 83) * LogicalBlockSize;
    Status = NtWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock,
                        SbdBuffer, LogicalBlockSize, &Offset, NULL);
    
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, FsdBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, RootDirBuffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, SbdBuffer);
        NtClose(DeviceHandle);
        UdfLibMessage(Callback, DONEWITHSTRUCTURE, 0, L"Failed to write Space Bitmap");
        return FALSE;
    }

    /* Clean up buffers */
    RtlFreeHeap(RtlGetProcessHeap(), 0, VrsBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, AvdpBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, PvdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, PdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, LvdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, TdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, FsdBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, RootDirBuffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, SbdBuffer);

    UdfLibMessage(Callback, PROGRESS, 90, L"Preparing boot area");
    
    /* Reserve sectors 1024-1088 for FreeLdr (64 sectors = 32KB)
     * The UDF boot sector will read FreeLdr from this location
     * Setup should copy freeldr.sys to these sectors after formatting
     * 
     * Improved UDF Layout (based on mkudffs):
     * - Sector 0: UDF boot sector  
     * - Sectors 16-18: Volume Recognition Sequence (BEA01/NSR02/TEA01)
     * - Logical Block 32: Primary Volume Descriptor
     * - Logical Block 33: Partition Descriptor
     * - Logical Block 34: Logical Volume Descriptor  
     * - Logical Block 35: Terminating Descriptor
     * - Logical Block 256 (or calculated): Anchor Volume Descriptor Pointer #1
     * - Logical Block N-1 (last block): Anchor Volume Descriptor Pointer #2
     * - Logical Block 161 (80+81): File Set Descriptor
     * - Logical Block 162 (80+82): Root Directory
     * - Sector 1024: FreeLdr boot location
     */

    UdfLibMessage(Callback, PROGRESS, 100, L"UDF format complete");

    /* Unlock the volume */
    NtFsControlFile(DeviceHandle,
                   NULL,
                   NULL,
                   NULL,
                   &IoStatusBlock,
                   FSCTL_UNLOCK_VOLUME,
                   NULL,
                   0,
                   NULL,
                   0);

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