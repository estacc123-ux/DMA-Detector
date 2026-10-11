#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../include/dma.h"

using namespace Dma;

// Bus walker.
// We don't touch the PnP device tree - just read config space over the legacy CF8/CFC port pair, the way firmware does before the OS boots, so functions with no driver bound still show up if they answer.
// Limits worth knowing:
//  - legacy CF8/CFC reads only reach the first 256 config bytes per function. Everything this walker pulls sits under offset 0x14 so that's fine; the >256-byte extended space needs ECAM/MMCONFIG instead (Microsoft's own writeup on the access paths:
//    https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/accessing-pci-device-configuration-space)
//  - direct port access can race whatever else owns config cycles, so reads stay short, dword-aligned and only happen inside the IOCTL path (same caution the OSR folks raise:
//    https://community.osr.com/t/accessing-the-configuration-space-of-attached-pci-devices/28596)
//  - 8 buses covers a typical consumer board; segmented server platforms would need ECAM segment support, out of scope here.
// An OSR thread on spotting DMA-cheat hardware is also where the "compare BAR/capability fingerprints" idea in bus.cpp's scoring comes from: https://community.osr.com/t/detecting-pcie-dma-based-cheating-hardware-in-online-games/55899

namespace DmaKernel {

static constexpr uint16_t CONFIG_ADDRESS_PORT = 0xCF8;
static constexpr uint16_t CONFIG_DATA_PORT = 0xCFC;
static constexpr uint8_t MAX_BUS = 8;
static constexpr uint8_t MAX_SLOT = 32;
static constexpr uint8_t MAX_FUNC = 8;
static constexpr uint32_t MAX_DEVICES = 128;

static uint32_t ReadConfigDword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
    const uint32_t address = (1u << 31)
        | (static_cast<uint32_t>(bus) << 16)
        | (static_cast<uint32_t>(slot) << 11)
        | (static_cast<uint32_t>(func) << 8)
        | (offset & 0xFC);

    __outdword(CONFIG_ADDRESS_PORT, address);
    return __indword(CONFIG_DATA_PORT);
}

static bool DevicePresent(uint8_t bus, uint8_t slot, uint8_t func)
{
    // 0xFFFF on vendor = nothing answered
    return (ReadConfigDword(bus, slot, func, 0x00) & 0xFFFF) != 0xFFFF;
}

static int WalkBus(WireDevice* out, int maxDevices)
{
    int count = 0;

    for (int bus = 0; bus < MAX_BUS && count < maxDevices; bus++) {
        for (int slot = 0; slot < MAX_SLOT && count < maxDevices; slot++) {
            if (!DevicePresent(static_cast<uint8_t>(bus), static_cast<uint8_t>(slot), 0)) {
                continue;
            }

            int funcs = 1;
            for (int func = 0; func < funcs && count < maxDevices; func++) {
                if (func > 0 && !DevicePresent(static_cast<uint8_t>(bus), static_cast<uint8_t>(slot), static_cast<uint8_t>(func))) {
                    continue;
                }

                // bit 7 of the header type on function 0 says whether the
                // device is multi-function
                if (func == 0) {
                    const uint8_t headerType = static_cast<uint8_t>((ReadConfigDword(static_cast<uint8_t>(bus), static_cast<uint8_t>(slot), 0, 0x0C) >> 16) & 0xFF);
                    if (headerType & 0x80) {
                        funcs = MAX_FUNC;
                    }
                }

                const uint8_t b = static_cast<uint8_t>(bus);
                const uint8_t s = static_cast<uint8_t>(slot);
                const uint8_t f = static_cast<uint8_t>(func);

                const uint32_t dw00 = ReadConfigDword(b, s, f, 0x00);
                const uint32_t dw04 = ReadConfigDword(b, s, f, 0x04);
                const uint32_t dw08 = ReadConfigDword(b, s, f, 0x08);
                const uint32_t dw0C = ReadConfigDword(b, s, f, 0x0C);
                const uint32_t dw10 = ReadConfigDword(b, s, f, 0x10);
                const uint32_t dw14 = ReadConfigDword(b, s, f, 0x14);

                WireDevice* dev = &out[count];
                RtlZeroMemory(dev, sizeof(WireDevice));
                dev->VendorId = static_cast<uint16_t>(dw00 & 0xFFFF);
                dev->DeviceId = static_cast<uint16_t>(dw00 >> 16);
                dev->Bus = b;
                dev->Slot = s;
                dev->Func = f;
                dev->BaseClass = static_cast<uint8_t>((dw08 >> 24) & 0xFF);
                dev->SubClass = static_cast<uint8_t>((dw08 >> 16) & 0xFF);
                dev->ProgIf = static_cast<uint8_t>((dw08 >> 8) & 0xFF);
                dev->RevId = static_cast<uint8_t>(dw08 & 0xFF);
                dev->HeaderType = static_cast<uint8_t>((dw0C >> 16) & 0xFF);
                dev->Command = static_cast<uint16_t>(dw04 & 0xFFFF);
                dev->Status = static_cast<uint16_t>(dw04 >> 16);
                dev->Bar0 = dw10;
                dev->Bar1 = dw14;
                count++;
            }
        }
    }

    return count;
}

} // namespace DmaKernel
