#include "dma.h"
#include <cstdio>
#include <cstring>

// Stand alone CLI. Prints the bus the way the driver saw it, risk-sorted.
// Usage:
//   DmaDetector.exe        normal table
//   DmaDetector.exe raw    tab-separated, for scripts
// Exit codes: 0 clean, 1 driver/bus failure, 2 suspicious, 3 known DMA.

using namespace Dma;

int main(int argc, char* argv[])
{
	const bool raw = argc > 1 && strcmp(argv[1], "raw") == 0;

	HANDLE driver = INVALID_HANDLE_VALUE;
	if (!OpenDriver(&driver)) {
		fprintf(stderr, "could not open \\\\.\\DmaDetector (error %lu)\n", GetLastError());
		fprintf(stderr, "create and start the service first, see README\n");
		return 1;
	}

	ScanReport report;
	if (!Scan(driver, &report)) {
		fprintf(stderr, "bus scan failed (driver is up but the readback broke)\n");
		CloseDriver(driver);
		return 1;
	}

	if (raw) {
		for (const DeviceEntry& d : report.Devices) {
			printf("%02x:%02x.%d\t%04x:%04x\t%s\t%s\t%s\t%s\n",
				d.Raw.Bus, d.Raw.Slot, d.Raw.Func,
				d.Raw.VendorId, d.Raw.DeviceId,
				RiskName(d.Risk),
				d.VendorName.empty() ? "?" : d.VendorName.c_str(),
				d.ClassName.c_str(),
				d.Note.c_str());
		}
	} else {
		printf("%zu devices visible, %u flagged, %u suspicious\n\n",
			report.Devices.size(), report.FlaggedCount, report.SuspiciousCount);

		for (const DeviceEntry& d : report.Devices) {
			printf("%02x:%02x.%d  %04x:%04x  %-9s  %-14.14s %-16.16s",
				d.Raw.Bus, d.Raw.Slot, d.Raw.Func,
				d.Raw.VendorId, d.Raw.DeviceId,
				RiskName(d.Risk),
				d.VendorName.empty() ? "?" : d.VendorName.c_str(),
				d.ClassName.c_str());
			if (!d.Note.empty()) {
				printf("  %s", d.Note.c_str());
			}
			printf("\n");
		}

		printf("\nnote: firmware can spoof ids, class codes and BARs, so none of\n");
		printf("this is proof by itself. Known DMA = stock/known cheat firmware,\n");
		printf("Suspicious = worth a manual look.\n");
	}

	CloseDriver(driver);

	if (report.FlaggedCount > 0) return 3;
	if (report.SuspiciousCount > 0) return 2;
	return 0;
}
