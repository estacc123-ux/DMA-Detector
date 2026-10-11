// DmaDetector - stand alone bus scanner driver.
//the whole point of this driver is that it talks to the PCI bus directly instead of asking Windows what's plugged in.
// Anti-cheat / DMA detection background that shaped the approach lives in pci.cpp (config-space limits) and lib/bus.cpp (known id list, sourced from the pcileech-fpga docs).
// The general idea of treating DMA hardware as something you fingerprint rather than trust the OS to report is the same one pcileech's own docs note when they say editing IDs alone doesn't beat a real detector:
// https://github.com/ufrisk/pcileech-fpga/blob/master/pciescreamer/build.md

#include "driver.h"
#include "pci.cpp"

#include <ntstrsafe.h>

using namespace Dma;
using namespace DmaKernel;

static PDEVICE_OBJECT g_DeviceObject = nullptr;
static UNICODE_STRING g_DevName {};
static UNICODE_STRING g_SymLink {};

static ULONG g_ScanCount = 0;
static LARGE_INTEGER g_LastScanTick {};

static NTSTATUS CreateClose(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchRequest(ULONG inLen, ULONG outLen, PVOID systemBuffer, ULONG* bytesReturned)
{
    *bytesReturned = 0;

    if (inLen < sizeof(uint32_t) || !systemBuffer) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    switch (*static_cast<uint32_t*>(systemBuffer)) {
        case static_cast<uint32_t>(Dma::RequestType::ScanBus): {
            if (outLen < FIELD_OFFSET(WireScanResult, Devices)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            const ULONG maxDevices = (outLen - FIELD_OFFSET(WireScanResult, Devices)) / sizeof(WireDevice);
            if (maxDevices == 0 || maxDevices > MAX_DEVICES) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            auto* result = static_cast<WireScanResult*>(systemBuffer);
            RtlZeroMemory(result, outLen);
            result->Count = static_cast<uint32_t>(WalkBus(result->Devices, static_cast<int>(maxDevices)));
            result->Status = STATUS_SUCCESS;
            result->ScanTick = KeQueryInterruptTime();
            *bytesReturned = FIELD_OFFSET(WireScanResult, Devices) + result->Count * sizeof(WireDevice);

            g_ScanCount++;
            g_LastScanTick.QuadPart = static_cast<LONGLONG>(result->ScanTick);
            return STATUS_SUCCESS;
        }

        case static_cast<uint32_t>(Dma::RequestType::QueryStats): {
            if (outLen < FIELD_OFFSET(WireScanResult, Devices)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            auto* result = static_cast<WireScanResult*>(systemBuffer);
            RtlZeroMemory(result, FIELD_OFFSET(WireScanResult, Devices));
            result->Status = STATUS_SUCCESS;
            result->Count = g_ScanCount;
            result->ScanTick = static_cast<uint64_t>(g_LastScanTick.QuadPart);
            *bytesReturned = FIELD_OFFSET(WireScanResult, Devices);
            return STATUS_SUCCESS;
        }

        default:
            return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);

    if (irpSp->Parameters.DeviceIoControl.IoControlCode != IOCTL_DMA_REQUEST) {
        DbgPrint("[DmaDetector] unknown IOCTL 0x%08X\n", irpSp->Parameters.DeviceIoControl.IoControlCode);
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    ULONG bytesReturned = 0;
    irp->IoStatus.Status = DispatchRequest(
        irpSp->Parameters.DeviceIoControl.InputBufferLength,
        irpSp->Parameters.DeviceIoControl.OutputBufferLength,
        irp->AssociatedIrp.SystemBuffer,
        &bytesReturned);
    irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    IoDeleteSymbolicLink(&g_SymLink);
    IoDeleteDevice(driverObject->DeviceObject);
    DbgPrint("[DmaDetector] unloaded\n");
}

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT driverObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(driverObject);
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS DmaDetectorInitialize(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    RtlInitUnicodeString(&g_DevName, DMA_DEVICE_NAME);
    RtlInitUnicodeString(&g_SymLink, DMA_SYMLINK_NAME);

    PDEVICE_OBJECT deviceObject = nullptr;
    NTSTATUS status = IoCreateDevice(
        driverObject,
        0,
        &g_DevName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DmaDetector] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLink, &g_DevName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DmaDetector] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driverObject->MajorFunction[i] = UnsupportedDispatch;
    }
    driverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = DriverUnload;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[DmaDetector] loaded\n");
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING driverName, PDRIVER_INITIALIZE initializationFunction);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    return IoCreateDriver(nullptr, DmaDetectorInitialize);
}
