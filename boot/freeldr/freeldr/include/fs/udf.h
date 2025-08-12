/*
 * PROJECT:     FreeLoader
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     UDF support for FreeLoader
 * COPYRIGHT:   Copyright 2024 ReactOS UDF Boot Project
 */

#pragma once

// UDF Constants
#define UDF_BLOCK_SIZE              2048
#define UDF_SECTOR_SIZE             512
#define UDF_ANCHOR_OFFSET           256
#define UDF_MAIN_ANCHOR_LOCATION    256

// UDF Magic Numbers
#define UDF_NSR_VERSION_2           "NSR02"
#define UDF_NSR_VERSION_3           "NSR03"

// UDF File Types
#define UDF_FT_UNSPECIFIED          0
#define UDF_FT_UNALLOCATED_SPACE     1
#define UDF_FT_PARTITION_INTEGRITY   2
#define UDF_FT_INDIRECT              3
#define UDF_FT_DIRECTORY             4
#define UDF_FT_RANDOM_ACCESS_BLOCK   5
#define UDF_FT_CHAR_SPECIAL          6
#define UDF_FT_BLOCK_SPECIAL         7
#define UDF_FT_REGULAR_FILE          8
#define UDF_FT_FIFO                  9
#define UDF_FT_SOCKET               10
#define UDF_FT_TERMINAL             11
#define UDF_FT_SYMBOLIC_LINK        12
#define UDF_FT_STREAM_DIRECTORY     13

typedef struct _UDF_FILE_INFO
{
    ULONG DeviceId;
    ULONGLONG Position;
    ULONGLONG FileSize;
    ULONG DirectoryLBA;
    ULONG FileLBA;
    ULONG FileEntry;
} UDF_FILE_INFO, *PUDF_FILE_INFO;

const DEVVTBL* UdfMount(ULONG DeviceId);
