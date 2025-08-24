////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
#include "udffs.h"

VOID
NTAPI
UDFDriverUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{
//    UNICODE_STRING uniWin32NameString;
    LARGE_INTEGER delay;

    //
    // All *THIS* driver needs to do is to delete the device object and the
    // symbolic link between our device name and the Win32 visible name.
    //
    // Almost every other driver ever written would need to do a
    // significant amount of work here deallocating stuff.
    //

    UDFPrint( ("UDF: Unloading!!\n") );

    // prevent mount oparations
    UdfData.Flags |= UDF_DATA_FLAGS_SHUTDOWN;

    // Clean up all kernel resources before entering wait loop to prevent Driver Verifier errors
    UDFPrint(("UDF: Cleaning up kernel resources\n"));
    
    // Clean up lookaside lists - this prevents BSOD about uncancelled lookaside lists
    UDFDestroyZones();
    
    // Clean up dynamically allocated memory
    if (UdfData.SavedRegPath.Buffer) {
        UDFPrint(("UDF: Freeing SavedRegPath.Buffer\n"));
        MyFreePool__(UdfData.SavedRegPath.Buffer);
        UdfData.SavedRegPath.Buffer = NULL;
        UdfData.SavedRegPath.Length = 0;
        UdfData.SavedRegPath.MaximumLength = 0;
    }

#ifdef UDF_DELAYED_CLOSE
    // Ensure all queued work items are completed before unload
    // This prevents Driver Verifier BSOD about uncancelled work items
    UDFPrint(("UDF: Flushing any pending work items\n"));
    
    // Wait for any pending close operations to complete
    // Check if there are pending delayed closes and wait for them
    if (UdfData.DelayedCloseCount > 0) {
        UDFPrint(("UDF: Waiting for %d delayed close operations to complete\n", UdfData.DelayedCloseCount));
        
        // Wait with reasonable timeout for pending operations to complete
        LARGE_INTEGER shortDelay;
        shortDelay.QuadPart = -1000000; // 100ms
        int maxWait = 50; // Max 5 seconds total
        
        while (UdfData.DelayedCloseCount > 0 && maxWait > 0) {
            KeDelayExecutionThread(KernelMode, FALSE, &shortDelay);
            maxWait--;
        }
    }
    
    // The work item and fast mutex are part of UdfData structure and will be
    // cleaned up when the driver unloads. We don't need to explicitly delete them
    // as they're not dynamically allocated, but we should ensure no work is pending.
#endif //UDF_DELAYED_CLOSE

    // wait for all volumes to be dismounted
    delay.QuadPart = 10*1000*1000*10;
    while(TRUE) {
        UDFPrint(("Poll...\n"));
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    // Create counted string version of our Win32 device name.


//    RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );


    // Delete the link from our device name to a name in the Win32 namespace.


//    IoDeleteSymbolicLink( &uniWin32NameString );


    // Finally delete our device object


//    IoDeleteDevice( DriverObject->DeviceObject );
}
