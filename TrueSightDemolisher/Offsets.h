#pragma once

#include "KernelReadWrite.h"

//
// TODO: convert away from hardcoded offsets
//

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

//
// Return the offset of UniqueProcessId from the start of EPROCESS
//
UINT GetProcessIdOffsetFromProcess(IKernelReadWrite* Rw);

// todo
UINT GetTokenOffsetFromProcess(IKernelReadWrite* Rw);

//
// Returns the address of an exported symbol by its name, given the image's base address
//
PVOID GetExportAddress(PVOID Base, const char* Name, IKernelReadWrite* Rw);


//
// Get the base address of ntoskrnl
//
PBYTE GetKernelBase();
