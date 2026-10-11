#pragma once
#include <ntifs.h>
#include "../include/dma.h"
#define DMA_DEVICE_NAME L"\\Device\\DmaDetector"

extern "C" NTSTATUS DmaDetectorInitialize(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath);
