#pragma once

#include <Windows.h>
#include <vector>

using Qword = ULONGLONG;

//
// Generic kernel read-write interface
//
class IKernelReadWrite {
public:
	virtual Qword ReadQword(PVOID Address) = 0;

	virtual void WriteQword(PVOID Address, Qword Value) = 0;

#define AlignUpToQword(Size) ((Size & ~(sizeof(Qword))) + sizeof(Qword))

	virtual std::vector<BYTE> ReadBuffer(PVOID Address, ULONG Length) {
		auto alignedLength = AlignUpToQword(Length);
		auto* buffer = new Qword[alignedLength / sizeof(Qword)];

		// copy data into buffer

		for (int i = 0; i < alignedLength / sizeof(Qword); ++i) {
			buffer[i] = this->ReadQword(Address);
		}

		// copy into vector and trim extra entries
		
		std::vector<BYTE> result((BYTE*)buffer, (BYTE*)(buffer)+alignedLength);
		result.erase(result.begin() + (alignedLength - Length), result.end());
		return result;
	}
	
	template <typename T>
	void ReadType(PVOID Address, T* Value) {
		std::vector<BYTE> contents = this->ReadBuffer(Address, sizeof(T));
		*Value = *reinterpret_cast<T*>(contents.data());
	}
};
