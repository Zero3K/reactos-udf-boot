/*
 * PROJECT:     FreeLoader
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     UDF support for FreeLoader
 * COPYRIGHT:   Copyright 2024 ReactOS UDF Boot Project
 */

#include <freeldr.h>
#include <debug.h>

DBG_DEFAULT_CHANNEL(FILESYSTEM);

#define TAG_UDF_INFO 'IfdU'
#define TAG_UDF_FILE 'FfdU'

struct UDF_INFO
{
    ULONG DeviceId;
    BOOLEAN IsValid;
};

struct UDF_INFO *UdfVolumes[MAX_FDS];

static ARC_STATUS UdfClose(ULONG FileId)
{
    PUDF_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);

    if (FileHandle)
    {
        FrLdrTempFree(FileHandle, TAG_UDF_FILE);
    }

    return ESUCCESS;
}

static ARC_STATUS UdfGetFileInformation(ULONG FileId, FILEINFORMATION* Information)
{
    PUDF_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);

    if (!FileHandle)
        return EBADF;

    RtlZeroMemory(Information, sizeof(FILEINFORMATION));
    Information->EndingAddress.QuadPart = FileHandle->FileSize;
    Information->CurrentAddress.QuadPart = FileHandle->Position;

    return ESUCCESS;
}

static ARC_STATUS UdfOpen(CHAR* Path, OPENMODE OpenMode, ULONG* FileId)
{
    PUDF_FILE_INFO FileHandle;

    if (OpenMode != OpenReadOnly)
        return EACCES;

    /* For now, just implement basic file access to freeldr.sys */
    if (_stricmp(Path, "\\freeldr.sys") != 0)
        return ENOENT;

    FileHandle = FrLdrTempAlloc(sizeof(UDF_FILE_INFO), TAG_UDF_FILE);
    if (!FileHandle)
        return ENOMEM;

    RtlZeroMemory(FileHandle, sizeof(UDF_FILE_INFO));

    /* Hardcode some values for freeldr.sys for basic functionality */
    FileHandle->DeviceId = FsGetDeviceId(*FileId);
    FileHandle->Position = 0;
    FileHandle->FileSize = 65536; // Assume 64KB for freeldr.sys
    FileHandle->FileLBA = 1024; // Assume it starts at sector 1024 (matches boot sector)

    FsSetDeviceSpecific(*FileId, FileHandle);

    return ESUCCESS;
}

static ARC_STATUS UdfRead(ULONG FileId, VOID* Buffer, ULONG Size, ULONG* BytesRead)
{
    PUDF_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);
    LARGE_INTEGER Position;
    ULONG SectorsToRead;
    ULONG BytesToRead;

    if (!FileHandle)
        return EBADF;

    if (FileHandle->Position >= FileHandle->FileSize)
    {
        *BytesRead = 0;
        return ESUCCESS;
    }

    BytesToRead = min(Size, (ULONG)(FileHandle->FileSize - FileHandle->Position));
    SectorsToRead = (BytesToRead + UDF_SECTOR_SIZE - 1) / UDF_SECTOR_SIZE;

    Position.QuadPart = (FileHandle->FileLBA + (FileHandle->Position / UDF_SECTOR_SIZE)) * UDF_SECTOR_SIZE;

    if (ArcSeek(FileHandle->DeviceId, &Position, SeekAbsolute) != ESUCCESS)
        return EIO;

    if (ArcRead(FileHandle->DeviceId, Buffer, SectorsToRead * UDF_SECTOR_SIZE, BytesRead) != ESUCCESS)
        return EIO;

    *BytesRead = min(*BytesRead, BytesToRead);
    FileHandle->Position += *BytesRead;

    return ESUCCESS;
}

static ARC_STATUS UdfSeek(ULONG FileId, LARGE_INTEGER* Position, SEEKMODE SeekMode)
{
    PUDF_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);

    if (!FileHandle)
        return EBADF;

    if (SeekMode != SeekAbsolute)
        return EINVAL;

    if (Position->QuadPart < 0 || Position->QuadPart > FileHandle->FileSize)
        return EINVAL;

    FileHandle->Position = Position->QuadPart;

    return ESUCCESS;
}

const DEVVTBL UdfFuncTable =
{
    UdfClose,
    UdfGetFileInformation,
    UdfOpen,
    UdfRead,
    UdfSeek,
    L"udf",
};

const DEVVTBL* UdfMount(ULONG DeviceId)
{
    struct UDF_INFO* UdfInfo;
    UCHAR Buffer[UDF_SECTOR_SIZE];
    LARGE_INTEGER Position;
    ULONG Count;

    TRACE("UdfMount(%lu)\n", DeviceId);

    /* Check if we can access the device */
    Position.QuadPart = 0;
    if (ArcSeek(DeviceId, &Position, SeekAbsolute) != ESUCCESS)
        return NULL;

    if (ArcRead(DeviceId, Buffer, sizeof(Buffer), &Count) != ESUCCESS)
        return NULL;

    /* Check for UDF Volume Recognition Sequence at sector 16 */
    Position.QuadPart = 16 * UDF_SECTOR_SIZE;
    if (ArcSeek(DeviceId, &Position, SeekAbsolute) != ESUCCESS)
        return NULL;

    if (ArcRead(DeviceId, Buffer, sizeof(Buffer), &Count) != ESUCCESS)
        return NULL;

    /* Check for NSR02 or NSR03 identifier */
    if (Count >= 5 && (memcmp(Buffer, "NSR02", 5) == 0 || memcmp(Buffer, "NSR03", 5) == 0))
    {
        TRACE("UdfMount: Found UDF Volume Recognition Sequence\n");
    }
    else
    {
        TRACE("UdfMount: No UDF Volume Recognition Sequence found\n");
        return NULL;
    }

    /* Create UDF info structure */
    UdfInfo = FrLdrTempAlloc(sizeof(struct UDF_INFO), TAG_UDF_INFO);
    if (!UdfInfo)
        return NULL;

    UdfInfo->DeviceId = DeviceId;
    UdfInfo->IsValid = TRUE;

    /* Remember UDF volume information */
    UdfVolumes[DeviceId] = UdfInfo;

    TRACE("UdfMount(%lu) success\n", DeviceId);
    return &UdfFuncTable;
}
