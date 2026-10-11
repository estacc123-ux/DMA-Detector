# DmaDetector

PCIe DMA-device scanner: finds classic DMA-cheat hardware
(PCILeech / Squirrel-class FPGA cards reading game memory from a second PC)
on the local machine.

Works without touching the Windows device tree: no SetupAPI, no WMI, no
registry. A tiny kernel driver reads PCI configuration space directly through
the legacy `CF8`/`CFC` port pair, the same mechanism the system firmware uses
before the OS boots, so devices with no bound driver still show up as long as
they answer on the bus.

## How the verdict works

| Verdict | Meaning |
|---|---|
| **Known DMA** | exact vendor:device match against a small firm buff of documented cheat-firmware identities (e.g. the PCILeech factory default `10ee:0666`) |
| **Suspicious** | FPGA-family vendor on a consumer board, or an unclassified device, or an unknown-vendor host bridge outside slot 0 |
| **Clean** | everything else |

Nothing here is proof by itself: DMA firmware can customize its vendor ID,
device ID, class code, BARs and serial number (the pcileech build guide says
so itself). Treat `Suspicious` as "go look closer" and `Known DMA` as "lazy
factory firmware present". Vendor numbers are checked against public PCI-SIG
/vendor listings, and the config-space reading model follows Microsoft's
[PCI configuration space documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/accessing-pci-device-configuration-space).

## Building

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Outputs land in `build/DmaDetector/Release/DmaDetector.exe` (CLI) and
`build/DmaDetectorDriver/<Config>/DmaDetectorDriver.sys` (kernel driver) when
the Windows Driver Kit is installed.

## Running

1. Install + start the driver service (elevated):

   ```bat
   sc create DmaDetector binPath= "<path>\DmaDetectorDriver.sys" type= kernel
   sc start DmaDetector
   ```

2. Run the CLI:

   ```bat
   DmaDetector.exe          :: normal table
   DmaDetector.exe raw      :: tab-separated detail for scripts
   ```

Exit codes: `0` clean, `1` driver/bus failure, `2` suspicious found,
`3` known DMA hardware found, so CI or a scheduled task can alert on
non-zero.

## Limitations (read before you trust it)

- Legacy CF8/CFC reads cover 8 PCI buses and the first 256 config bytes per
  function. Multi-segment servers and ECAM-only platforms are out of scope.
- Raw port access is racy by nature and we keep reads short, aligned, and driven
  only from the IOCTL path.
- A silent/faulty card doesn't answer config reads, absence of an entry is
  not evidence of absence.
- Spoofed firmware can defeat ID matching; config-space fingerprinting
  (BAR layout, capabilities, MSI structure) is the natural next step and
  is not in this release.
