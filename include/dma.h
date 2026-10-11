#pragma once
// Shared by both the ring3 lib and the kernel driver.
// Anything that touches the user-mode headers or the STL is guarded off with `_KMODE - kernel builds` compile with /kernel and no default CRT, and dragging Windows.h or STL headers in there breaks it in a interesting ways.
#ifndef _KMODE
#include <Windows.h>
#include <string>
#include <vector>
#endif

#include <cstdint>

namespace Dma {
#define DMA_SYMLINK_NAME L"\\DosDevices\\DmaDetector"
#define IOCTL_DMA_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// wire structs shared with the driver.
// METHOD_BUFFERED, fixed layout, no pointers - ring3 just fills a buffer and reads one back.
// if you edit these, edit both sides; the kernel build compiles with /kernel so keep anything clever out of the kernel-side part of this header.
enum class RequestType : uint32_t {
	ScanBus = 0,
	QueryStats = 1,
};
// ty "https://www.vergiliusproject.com/kernels" for this
// One device, straight from config space. Everything past this (scoring, vendor names) is derived ring3-side.
struct WireDevice {
	uint16_t VendorId;
	uint16_t DeviceId;
	uint8_t Bus;
	uint8_t Slot;
	uint8_t Func;
	uint8_t BaseClass;
	uint8_t SubClass;
	uint8_t ProgIf;
	uint8_t HeaderType;
	uint8_t RevId;
	uint16_t Command;
	uint16_t Status;
	uint32_t Bar0;
	uint32_t Bar1;
};
static_assert(sizeof(WireDevice) == 24, "wire layout drifted");

struct WireScanResult {
	uint32_t Status;
	uint32_t Count;
	uint64_t ScanTick;
	WireDevice Devices[1];
};

enum class Risk : uint8_t {
	Clean = 0,
	Suspicious = 1,
	KnownDma = 2,
};

#ifndef _KMODE
struct DeviceEntry {
	WireDevice Raw;
	Risk Risk;
	std::string VendorName;
	std::string ClassName;
	std::string Note;
};

struct ScanReport {
	std::vector<DeviceEntry> Devices;
	uint32_t FlaggedCount = 0;
	uint32_t SuspiciousCount = 0;
	uint64_t ScanTick = 0;
	bool DriverPresent = false;
	bool BusAccessible = false;
};

bool OpenDriver(HANDLE* outHandle);
void CloseDriver(HANDLE handle);

// Full bus walk + scoring. Returns false when the driver isn't there at all.
bool Scan(HANDLE driver, ScanReport* report);

Risk ScoreDevice(const WireDevice& dev, std::string* vendorName, std::string* className, std::string* note);
const char* RiskName(Risk risk);
const char* VendorName(uint16_t vendorId);
const char* ClassName(uint8_t base, uint8_t sub);
#endif

} // namespace Dma
