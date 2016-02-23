#pragma once

#include "stdafx.h"

DWORD HvxPeekDWORD(QWORD Address);
QWORD HvxPeekQWORD(QWORD Address);
VOID HvxPeekBytes(QWORD Address, PVOID pbBuffer, DWORD dwSize);

VOID HvxPokeDWORD(QWORD Address, DWORD Value);
VOID HvxPokeQWORD(QWORD Address, QWORD Value);
VOID HvxPokeBytes(QWORD Address, PVOID pbBuffer, DWORD dwSize);