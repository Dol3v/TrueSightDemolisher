
#include "Offsets.h"
#include "Utils.h"

#include <Psapi.h>


#define Rva2Address(Rva, Base) ((Rva) + reinterpret_cast<PBYTE>((Base)))

static PVOID GetExportAddress(PVOID Base, const char* Name, IKernelReadWrite* Rw) {

	//
	// Get export directory
	//

	auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);

	LONG e_lfanew = 0;
	Rw->ReadType<LONG>(&dosHeader->e_lfanew, &e_lfanew);
	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(Rva2Address(e_lfanew, Base));


	IMAGE_DATA_DIRECTORY exportDataDirectory = { 0 };
	Rw->ReadType<IMAGE_DATA_DIRECTORY>(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT], &exportDataDirectory);

	IMAGE_EXPORT_DIRECTORY exportDirectory = { 0 };
	Rw->ReadType<IMAGE_EXPORT_DIRECTORY>(Rva2Address(exportDataDirectory.VirtualAddress, Base), &exportDirectory);

	//
	// Find export address by name
	//

	PBYTE exportedNames = Rva2Address(exportDirectory.AddressOfNames, Base);
	PBYTE exportAddresses = Rva2Address(exportDirectory.AddressOfFunctions, Base);


	// TODO: finish

	return nullptr;
}

UINT GetProcessIdOffsetFromProcess(IKernelReadWrite* Rw) {

	static UINT cachedOffset = 0;
	if (cachedOffset != 0) {
		return cachedOffset;
	}

	//
	// The PsGetProcessId function can reveal to us the offset of the ProcessId from the start of _EPROCESS:
	// It's structured as follows:
	//	mov rax, [rcx+_EPROCESS.UniqueProcessId]
	// Hence we can simply read it and parse the offset :)
	//

	PVOID kernelBase = GetKernelBase();

	PVOID PsGetProcessId = GetExportAddress(kernelBase, "PsGetProcessId", Rw);
	std::vector<BYTE> instructions = Rw->ReadBuffer(PsGetProcessId, 7);

	// start of mov rcx, [rax+?]
	constexpr UINT MovRaxRcx = 0x818b48;

	// compare first three bytes
	if ((*reinterpret_cast<UINT*>(instructions.data()) & 0x00ffffff) != MovRaxRcx) {
		RaiseError("Failed to extract Process Id from PsGetProcessId");
	}
	UINT offset = *reinterpret_cast<UINT*>(instructions.data() + 3);
	cachedOffset = offset;
	return offset;
}

UINT GetTokenOffsetFromProcess(IKernelReadWrite* Rw)
{
	return 0;
}

PBYTE GetKernelBase() {

	// why can't we have functools.cache :(
	static PBYTE cachedAddress = nullptr;
	if (cachedAddress) {
		cachedAddress;
	}

	// the first driver is ntoskrnl

	PVOID firstDriver = nullptr;
	DWORD driversSize = 0;
	EnumDeviceDrivers(&firstDriver, sizeof(PVOID), &driversSize);

	return (PBYTE)firstDriver;
}