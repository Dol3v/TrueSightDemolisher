#pragma once

#include "KernelReadWrite.h"

//
// TODO: convert away from hardcoded offsets
//

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
