#include "dma.h"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace Dma {

// DMA-cheat firmware almost always starts life as stock pcileech bitstreams.
// The factory default shows up as 10ee:0666 ("Xilinx Ethernet Adapter") - that exact id pair is published in the pcileech-fpga build guides for Screamer and Squirrel:
//   https://github.com/ufrisk/pcileech-fpga/blob/master/pciescreamer/build.md
//   https://github.com/ufrisk/pcileech-fpga/blob/master/PCIeSquirrel/build.md
// Beyond that we deliberately keep the table small: the same guides show that
// firmware can rewrite its own vendor id, device id, class code and BARs, so
// ID matching is a fingerprint, not proof. A stock-firmware card or an FPGA
// vendor on a consumer board is worth flagging; anything else we stay quiet
// about. The line of thinking (config-space fingerprint comparison instead of
// ID lists alone) tracks the DMA-cheat community's own writeup of what
// anti-cheats look for: https://dma.lystic.dev/anticheat-evasion/detection-vectors
struct DevMatch {
	uint16_t Vendor;
	uint16_t Device;
	const char* Name;
};

static const DevMatch s_KnownDevices[] = {
	{ 0x10ee, 0x0666, "PCILeech default firmware (fake Xilinx Ethernet)" },
	{ 0x10ee, 0x7011, "Xilinx AXI PCIe bridge (common spoof base)" },
	{ 0x10ee, 0x7021, "Xilinx DMA/Bridge subsystem" },
	{ 0x1412, 0x124b, "Tiger Jet bridge (classic pcileech spoof target)" },
};

// FPGA vendors that have no business sitting in a gaming machine.
static const uint16_t s_FpgaVendors[] = {
	0x10ee, // Xilinx/AMD
	0x1204, // Lattice
	0x1172, // Altera/Intel
	0x534d, // Dini Group
};

static const char* ClassNameFromTable(uint8_t base, uint8_t sub)
{
	// trimmed to the classes that actually tell us something
	switch (base) {
		case 0x00: return "Legacy/Unclassified";
		case 0x01: return "Mass storage";
		case 0x02: return "Network";
		case 0x03: return "Display";
		case 0x05: return "Memory controller";
		case 0x06:
			if (sub == 0x00) return "Host bridge";
			if (sub == 0x01) return "ISA bridge";
			if (sub == 0x04) return "PCI bridge";
			return "Bridge";
		case 0x0C: return "Bus (USB/SM etc)";
	}
	return "Other";
}

const char* ClassName(uint8_t base, uint8_t sub)
{
	return ClassNameFromTable(base, sub);
}

static const struct { uint16_t Id; const char* Name; } s_Vendors[] = {
	{ 0x8086, "Intel" },
	{ 0x1022, "AMD" },
	{ 0x10de, "NVIDIA" },
	{ 0x1002, "AMD/ATI" },
	{ 0x10ee, "Xilinx/AMD" },
	{ 0x1172, "Altera" },
	{ 0x1204, "Lattice" },
	{ 0x1412, "Tiger Jet" },
	{ 0x14c3, "MediaTek" },
	{ 0x168c, "Qualcomm Atheros" },
	{ 0x144d, "Samsung" },
	{ 0x1b4b, "Marvell" },
	{ 0x15ad, "VMware" },
	{ 0x1af4, "Red Hat virtio" },
	{ 0x1b36, "QEMU" },
};

const char* VendorName(uint16_t id)
{
	for (const auto& v : s_Vendors) {
		if (v.Id == id) return v.Name;
	}
	return nullptr;
}

Risk ScoreDevice(const WireDevice& dev, std::string* vendorName, std::string* className, std::string* note)
{
	note->clear();
	*className = ClassName(dev.BaseClass, dev.SubClass);

	if (const char* name = VendorName(dev.VendorId)) {
		*vendorName = name;
	} else {
		vendorName->clear();
	}

	for (const auto& m : s_KnownDevices) {
		if (m.Vendor == dev.VendorId && m.Device == dev.DeviceId) {
			*note = m.Name;
			return Risk::KnownDma;
		}
	}

	for (uint16_t v : s_FpgaVendors) {
		if (v == dev.VendorId) {
			*note = "FPGA vendor present - stock bitstream or unloaded custom firmware";
			return Risk::Suspicious;
		}
	}

	// An unclassified device is odd on a consumer board. Not proof of
	// anything - class 0xFF is the PCI-SIG "unassigned class" code and a few
	// legit devices ship with it (PCI-SIG Code & ID Assignment Spec) - but a
	// detector that ignores it gets caught flat-footed when cheap firmware
	// forgets to write a class in. Worth an eye, nothing more.
	if (dev.BaseClass == 0xFF || dev.BaseClass == 0x00) {
		*note = "unclassified device";
		return Risk::Suspicious;
	}

	return Risk::Clean;
}

const char* RiskName(Risk risk)
{
	switch (risk) {
		case Risk::Clean: return "Clean";
		case Risk::Suspicious: return "Suspicious";
		case Risk::KnownDma: return "Known DMA";
	}
	return "?";
}

bool OpenDriver(HANDLE* outHandle)
{
	*outHandle = CreateFileW(
		L"\\\\.\\DmaDetector",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr);
	return *outHandle != INVALID_HANDLE_VALUE;
}

void CloseDriver(HANDLE handle)
{
	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
	}
}

bool Scan(HANDLE driver, ScanReport* report)
{
	if (driver == INVALID_HANDLE_VALUE || !report) {
		return false;
	}

	report->DriverPresent = true;

	// first request expects a small result set; the driver tells us if the
	// buffer was too small and we grow once instead of looping blind.
	constexpr size_t headerSize = sizeof(uint32_t) * 2 + sizeof(uint64_t);
	std::vector<uint8_t> out(headerSize + 128 * sizeof(WireDevice));

	uint32_t type = static_cast<uint32_t>(RequestType::ScanBus);
	std::vector<uint8_t> in(sizeof(type));
	memcpy(in.data(), &type, sizeof(type));

	DWORD returned = 0;
	if (!DeviceIoControl(driver, IOCTL_DMA_REQUEST, in.data(), static_cast<DWORD>(in.size()), out.data(), static_cast<DWORD>(out.size()), &returned, nullptr)) {
		return false;
	}

	const auto* result = reinterpret_cast<const WireScanResult*>(out.data());
	if (returned < headerSize || result->Count > 128) {
		return false;
	}

	report->BusAccessible = true;
	report->ScanTick = result->ScanTick;

	for (uint32_t i = 0; i < result->Count; i++) {
		DeviceEntry entry;
		entry.Raw = result->Devices[i];
		entry.Risk = ScoreDevice(entry.Raw, &entry.VendorName, &entry.ClassName, &entry.Note);
		if (entry.Risk == Risk::KnownDma) report->FlaggedCount++;
		else if (entry.Risk == Risk::Suspicious) report->SuspiciousCount++;
		report->Devices.push_back(entry);
	}

	// risky stuff first, then bus order
	std::sort(report->Devices.begin(), report->Devices.end(), [](const DeviceEntry& a, const DeviceEntry& b) {
		if (a.Risk != b.Risk) return static_cast<int>(a.Risk) > static_cast<int>(b.Risk);
		if (a.Raw.Bus != b.Raw.Bus) return a.Raw.Bus < b.Raw.Bus;
		if (a.Raw.Slot != b.Raw.Slot) return a.Raw.Slot < b.Raw.Slot;
		return a.Raw.Func < b.Raw.Func;
	});

	return true;
}

} // namespace Dma
