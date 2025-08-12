/*
 * PROJECT:     FreeLoader
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     UDF volume boot sector for FreeLoader
 * COPYRIGHT:   Copyright 2024 ReactOS UDF Boot Project
 */

#include <asm.inc>
#include <freeldr/include/arch/pc/x86common.h>

.code16

start:
    jmp short main
    nop

// UDF Volume Boot Sector fields
BootDrive:
    .byte 0
PartitionStartLBA:
    .quad HEX(3f) // default value, will be overwritten by setup

main:
    xor eax, eax             // Setup segment registers
    mov ds, ax               // Make DS correct
    mov es, ax               // Make ES correct
    mov ss, ax               // Make SS correct
    mov sp, HEX(7c00)        // Setup a stack
    mov bp, sp

    mov byte ptr [BootDrive], dl

// Check if this computer supports extended reads
CheckInt13hExtensions:
    mov  ah, HEX(41)                        // AH = 41h
    mov  bx, HEX(55aa)                      // BX = 55AAh
    int  HEX(13)                            // IBM/MS INT 13 Extensions - INSTALLATION CHECK
    jc   PrintDiskError                     // CF set on error (extensions not supported)
    cmp  bx, HEX(aa55)                      // BX = AA55h if installed
    jne  PrintDiskError
    test cl, 1                              // si = API subset support bitmap
    jz   PrintDiskError                     // Bit 0, extended disk access functions (AH=42h-44h,47h,48h) supported

// For now, just load FreeLDR from a known location
// In a full UDF implementation, this would parse UDF structures
// to find and load freeldr.sys
LoadFreeLdr:
    mov  eax, 2                             // Start reading from sector 2
    mov  cx, 64                             // Read 64 sectors (32KB)
    mov  bx, FREELDR_BASE                   // Load to FREELDR_BASE
    call ReadSectors

    mov  dl, byte ptr [BootDrive]           // Load boot drive into DL

    /* Transfer execution to the bootloader */
    ljmp16 0, FREELDR_BASE

// Reads logical sectors from disk
// INPUT:
// - EAX logical sector number to start reading from
// - CX number of sectors to read
// - ES:BX destination buffer
ReadSectors:
    pushad                                  // Save all registers

ReadSectors_loop:
    cmp  cx, 8                              // Maximum sectors per call
    jbe  ReadSectorsSetupDiskAddressPacket  // If we are reading less than 9 sectors then just do the read
    push cx
    mov  cx, 8                              // Otherwise read only 8 sectors on this loop iteration
    call ReadSectorsSetupDiskAddressPacket
    pop  cx
    sub  cx, 8                              // Subtract 8 from sectors to read
    add  eax, 8                             // Add 8 to logical sector number
    add  bx, HEX(1000)                      // Add 4096 to buffer offset (8 * 512)
    jmp  ReadSectors_loop

ReadSectorsSetupDiskAddressPacket:
    add  eax, dword ptr [PartitionStartLBA] // Add partition start LBA
    adc  edx, dword ptr [PartitionStartLBA+4]

    push edx
    push eax                                // Put 64-bit logical block address on stack
    push es                                 // Put transfer segment on stack
    push bx                                 // Put transfer offset on stack
    push cx                                 // Set transfer count
    push 16                                 // Set size of packet to 10h
    mov  si, sp                             // Setup disk address packet on stack

    mov  dl, byte ptr [BootDrive]           // Drive number
    mov  ah, HEX(42)                        // Int 13h, AH = 42h - Extended Read
    int  HEX(13)                            // Call BIOS
    jc   PrintDiskError                     // If the read failed then abort

    add  sp, 16                             // Remove disk address packet from stack
    popad                                   // Restore all registers
    ret

// Displays a disk error message and reboots
PrintDiskError:
    mov  si, msgDiskError                   // Load disk error message
    call PutChars                           // Display it

Reboot:
    lea  si, [msgAnyKey]                    // Press any key message
    call PutChars                           // Display it
    xor  ax, ax
    int  HEX(16)                            // Wait for a keypress
    int  HEX(19)                            // Reboot

PutChars:
    lodsb
    or   al, al
    jz   short Done
    call PutCharsCallBios
    jmp  short PutChars
PutCharsCallBios:
    mov  ah, HEX(0e)
    mov  bx, HEX(07)
    int  HEX(10)
    ret
Done:
    mov  al, HEX(0d)
    call PutCharsCallBios
    mov  al, HEX(0a)
    call PutCharsCallBios
    ret

msgDiskError:
    .asciz "UDF disk error"
msgAnyKey:
    .asciz "Press any key to restart"

.org 510
    .word HEX(aa55)       // BootSector signature

.endcode16

END
