#pragma once

#include "KernelReadWrite.h"

template <typename T>
class KernelPtr {
public:

	KernelPtr(T* Pointer, IKernelReadWrite* Rw) : m_Ptr(Pointer), m_Rw(Rw) {}

	T operator*() {

	}

	class ArrowHelper {
		ArrowHelper(KernelPtr& Pointer) : m_Ptr(Pointer) {}

		T* operator->() {
			return &*m_Ptr;
		}

	private:
		KernelPtr& m_Ptr;
	};



private:
	PBYTE m_Ptr;
	IKernelReadWrite* m_Rw;
};