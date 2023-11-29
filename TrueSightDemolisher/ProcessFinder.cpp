#include "ProcessFinder.h"

ProcessFinder::ProcessFinder(IKernelReadWrite& Rw) : m_Rw(&Rw), m_ProcessListHead(0) {

	this->m_ProcessListHead = this->GetProcessListHead();
}

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

	return nullptr;
}

static PVOID GetKernelBase() {

	// cache calculation: kernel base address isn't bound to change unless we reboot

	static PVOID cachedBaseAddress = nullptr;
	if (cachedBaseAddress)
		return cachedBaseAddress;

	return nullptr;
}

PVOID ProcessFinder::GetProcessListHead() {
	auto* kernelBase = GetKernelBase();
	auto* processListHead = GetExportAddress(kernelBase, "PsActiveProcessHead", this->m_Rw);

	return 0;
}

static UINT GetProcessIdOffset(IKernelReadWrite* Rw) {

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
		// TODO handle failure
	}
	UINT offset = *reinterpret_cast<UINT*>(instructions.data() + 3);
	cachedOffset = offset;
	return offset;
}

PVOID ProcessFinder::FindProcessById(DWORD ProcessId)
{
	return PVOID();
}


