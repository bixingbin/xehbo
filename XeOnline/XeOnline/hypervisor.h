#pragma once
#include "stdafx.h"

namespace xbox {
	namespace hypervisor {
		HRESULT reloadKv();
		DWORD peekDword(QWORD Address);
		QWORD peekQword(QWORD Address);
		VOID peekBytes(QWORD Address, PVOID pbBuffer, DWORD dwSize);

		VOID pokeDword(QWORD Address, DWORD Value);
		VOID pokeQword(QWORD Address, QWORD Value);
		VOID pokeBytes(QWORD Address, PVOID pbBuffer, DWORD dwSize);

		PBYTE getCpuKey();
	}
}