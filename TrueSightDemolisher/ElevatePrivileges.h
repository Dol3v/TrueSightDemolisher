#pragma once

#include "KernelReadWrite.h"

NTSTATUS ElevatePrivilges(IKernelReadWrite& Rw, DWORD ProcessId);
