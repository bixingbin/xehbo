#include "stdafx.h"

QWORD __declspec(naked) HvxPeekPoke(QWORD Source, QWORD Destination, QWORD Size)
{
	__asm
	{
		mr r7, r5
		mr r6, r4
		mr r5, r3
		li r4, 5
		lis r3, 0x7262
		ori r3, r3, 0x7472
		li r0, 0x0
		sc
		blr
	}
}

DWORD HvxPeekDWORD(QWORD Address)
{
	DWORD ret = 0;
	HvxPeekBytes(Address, (PVOID)&ret, 4);
	return ret;
}

QWORD HvxPeekQWORD(QWORD Address)
{
	QWORD ret = 0;
	HvxPeekBytes(Address, (PVOID)&ret, 8);
	return ret;
}

VOID HvxPokeDWORD(QWORD Address, DWORD Value)
{
	HvxPokeBytes(Address, (PVOID)&Value, 4);
}

VOID HvxPokeQWORD(QWORD Address, QWORD Value)
{
	HvxPokeBytes(Address, (PVOID)&Value, 8);
}

VOID HvxPeekBytes(QWORD Address, PVOID Buffer, DWORD Size)
{
	PVOID data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	HvxPeekPoke(Address, 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(data), Size);
	memcpy(Buffer, data, Size);
	XPhysicalFree(data);
}

VOID HvxPokeBytes(QWORD Address, PVOID Buffer, DWORD Size)
{
	PVOID data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	memcpy(data, Buffer, Size);
	HvxPeekPoke(0x8000000000000000 | (DWORD)MmGetPhysicalAddress(data), Address, Size);
	XPhysicalFree(data);
}