#pragma once
#include "stdafx.h"

typedef struct _LAUNCH_SYS_MSG {
	XNOTIFYQUEUEUI_TYPE Type;
	PWCHAR Message;
	DWORD Delay;
} LAUNCH_SYS_MSG, *PLAUNCH_SYS_MSG;

static BOOL(__cdecl *dlaunchSetOptValByName)(CONST PCHAR optName, PDWORD val); // set when setLiveBlock is called
static HRESULT(__cdecl *DevSetMemory)(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf, LPDWORD pcbRet); // set when xbox::utilities::setMemory is called
static LAUNCH_SYS_MSG notifyData;

namespace xbox {
	namespace utilities {
		VOID log(const CHAR* strFormat, ...);
		HRESULT setLiveBlock(BOOL enabled);
		VOID rebootToDash();
		VOID doErrShutdown(WCHAR* msg, BOOL reboot = FALSE);
		VOID patchInJump(DWORD* Address, DWORD Destination, BOOL Linked);
		VOID patchInBranch(DWORD* Address, DWORD Destination, BOOL Linked);
		FARPROC resolveFunction(CHAR* ModuleName, DWORD Ordinal);
		DWORD getModuleImportCallAddress(LDR_DATA_TABLE_ENTRY* moduleHandle, CHAR* ImportedModuleName, DWORD Ordinal);
		DWORD patchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
		DWORD patchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
		BOOL readFile(const CHAR* fileName, PVOID pBuffer, DWORD cbBuffer);
		BOOL writeFile(const CHAR* FilePath, PVOID pBuffer, DWORD Size);
		HRESULT setMemory(VOID* Destination, DWORD Value);
		HRESULT setMemory(VOID* Destination, VOID* Source, DWORD Length);
		DWORD applyPatches(VOID* patches);
		HRESULT applyDefaultPatches();
		HRESULT mountSystem();
		VOID notify(PWCHAR displayText, DWORD dwDelay = 0, XNOTIFYQUEUEUI_TYPE notifyType = XNOTIFYUI_TYPE_CONSOLEMESSAGE);
		VOID createThread(PVOID lpStartAddress, BOOL systemThread = TRUE, DWORD dwHardwareThread = 4);
	}
}