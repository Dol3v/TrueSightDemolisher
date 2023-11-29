#pragma once

#include "KernelReadWrite.h"

//
// Finds the address of EPROCESS objects
//
class ProcessFinder {
public:
	ProcessFinder(IKernelReadWrite& Rw);

	PVOID FindProcessById(DWORD ProcessId);

private:
	PVOID GetProcessListHead();

private:
	//
	// Kernel read-write interface
	//
	IKernelReadWrite* m_Rw;

	//
	// Address of ActiveProcessLinks: Process list 
	//
	PVOID m_ProcessListHead;
};