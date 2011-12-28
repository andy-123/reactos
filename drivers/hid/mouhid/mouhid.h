#pragma once

#define _HIDPI_NO_FUNCTION_MACROS_
#include <ntddk.h>
#include <hidclass.h>
#include <hidpddi.h>
#include <hidpi.h>
#include <debug.h>
#include <ntddmou.h>
#include <kbdmou.h>


typedef struct
{
    //
    // lower device object
    //
    PDEVICE_OBJECT NextDeviceObject;

    //
    // irp which is used for reading input reports
    //
    PIRP Irp;

    //
    // event 
    //
    KEVENT Event;

    //
    // device object for class callback
    //
    PDEVICE_OBJECT ClassDeviceObject;

    //
    // class callback
    //
    PVOID ClassService;

    //
    // mouse type
    //
    USHORT MouseIdentifier;

    //
    // wheel usage page
    //
    USHORT WheelUsagePage;

    //
    // usage list length
    //
    USHORT UsageListLength;

    //
    // current usage list length
    //
    PUSAGE CurrentUsageList;

    //
    // previous usage list
    //
    PUSAGE PreviousUsageList;

    //
    // removed usage item list
    //
    PUSAGE BreakUsageList;

    //
    // new item usage list
    //
    PUSAGE MakeUsageList;

    //
    // preparsed data
    //
    PVOID PreparsedData;

    //
    // mdl for reading input report
    //
    PMDL ReportMDL;

    //
    // input report buffer
    //
    PUCHAR Report;

    //
    // input report length
    //
    ULONG ReportLength;

    //
    // file object the device is reading reports from
    //
    PFILE_OBJECT FileObject;

}MOUHID_DEVICE_EXTENSION, *PMOUHID_DEVICE_EXTENSION;


NTSTATUS
MouHid_InitiateRead(
    IN PDEVICE_OBJECT DeviceObject);
