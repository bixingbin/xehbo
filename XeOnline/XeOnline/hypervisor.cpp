#include "stdafx.h"

static BYTE call8EINit_Retail[28] = {
	0x38, 0x60, 0x00, 0x00, 0x48, 0x00, 0xB1, 0x2B, 0x3C, 0x60, 0xBE, 0xEF, 0x38, 0x21, 0x00, 0x10,
	0xE9, 0x81, 0xFF, 0xF8, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
};

static BYTE call8EInit_Devkit[28] = {
	0x38, 0x60, 0x00, 0x00, 0x48, 0x00, 0xAD, 0xA3, 0x3C, 0x60, 0xBE, 0xEF, 0x38, 0x21, 0x00, 0x10,
	0xE9, 0x81, 0xFF, 0xF8, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
};


QWORD __declspec(naked) HvxFreebootCall(DWORD Type, QWORD Source, QWORD Destination, QWORD Size) // 4 = execute code, 5 = peek / poke
{
	__asm
	{
		mr r7, r6
		mr r6, r5
		mr r5, r4
		mr r4, r3
		lis r3, 0x7262
		ori r3, r3, 0x7472
		li r0, 0x0
		sc
		blr
	}
}

namespace xbox {
	namespace hypervisor {
		HRESULT reloadKv()
		{
			PBYTE physBuff = (PBYTE)XPhysicalAlloc(0x100, MAXULONG_PTR, 0, MEM_LARGE_PAGES | PAGE_READWRITE | PAGE_NOCACHE);

			if (physBuff == NULL)
				return E_FAIL;

			ZeroMemory(physBuff, 0x100);
			memcpy(physBuff, global::isDevkit ? call8EInit_Devkit : call8EINit_Retail, sizeof(call8EINit_Retail));

			if (HvxFreebootCall(4, 0xFE00, 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(physBuff), 7) == 0)
			{
				XPhysicalFree(physBuff);
				return E_FAIL;
			}

			XPhysicalFree(physBuff);
			return ERROR_SUCCESS;
		}

		DWORD peekDword(QWORD Address)
		{
			DWORD ret = 0;
			peekBytes(Address, (PVOID)&ret, 4);
			return ret;
		}

		QWORD peekQword(QWORD Address)
		{
			QWORD ret = 0;
			peekBytes(Address, (PVOID)&ret, 8);
			return ret;
		}

		VOID peekBytes(QWORD Address, PVOID Buffer, DWORD Size)
		{
			PVOID data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
			HvxFreebootCall(5, Address, 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(data), Size);
			memcpy(Buffer, data, Size);
			XPhysicalFree(data);
		}

		VOID pokeDword(QWORD Address, DWORD Value)
		{
			pokeBytes(Address, (PVOID)&Value, 4);
		}

		VOID pokeQword(QWORD Address, QWORD Value)
		{
			pokeBytes(Address, (PVOID)&Value, 8);
		}

		VOID pokeBytes(QWORD Address, PVOID Buffer, DWORD Size)
		{
			PVOID data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
			memcpy(data, Buffer, Size);
			HvxFreebootCall(5, 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(data), Address, Size);
			XPhysicalFree(data);
		}

		PBYTE getCpuKey()
		{
			BYTE fuseCpu[0x10];
			BYTE hvCpu[0x10];

			peekBytes(0x20, hvCpu, 0x10);
			*(QWORD*)(fuseCpu) = peekQword(0x8000020000020000 + (3 * 0x200));
			*(QWORD*)(fuseCpu + 8) = peekQword(0x8000020000020000 + (5 * 0x200));

			if (memcmp(fuseCpu, hvCpu, 0x10) != 0)
				VdDisplayFatalError(69);

			return fuseCpu;
		}
	}
}