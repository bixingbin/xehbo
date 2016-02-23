#pragma once
#include "stdafx.h"

BOOL InitializeHooks();
NTSTATUS XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress);
NTSTATUS XexLoadExecutableHook(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion);
NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle);