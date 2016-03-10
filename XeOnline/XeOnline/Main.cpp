#include "stdafx.h"

HRESULT Initialize()
{
	xbox::utilities::setLiveBlock(TRUE);

	if (xbox::utilities::mountSystem() != S_OK)
		return E_FAIL;
		
	if (XboxKrnlVersion->Build != global::supportedVersion && !global::isDevkit)
	{
		xbox::utilities::log("Unsupported kernel version.");
		return E_FAIL;
	}

	if(xbox::hooks::initialize() != S_OK)
		return E_FAIL;

	if (xbox::utilities::applyDefaultPatches() != S_OK)
		return E_FAIL;

	if (xbox::keyvault::initialize() != S_OK)
	{
		xbox::utilities::log("Failed to set keyvault.");
		return E_FAIL;
	}

	server::main::initialize();
	return S_OK;
}

VOID DllMain(HANDLE hModule)
{
	// decrypt the strings (calling it here so they cant see we use XeCryptRc4)
	//if (cryptData[0] != 0x78624372)
	//	XeCryptRc4((PBYTE)cryptData, 8, (PBYTE)(PVOID)(~cryptData[2] ^ 0x17394), ~cryptData[3] ^ 0x61539);

	global::isDevkit = *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE;
	global::modules::client = (PLDR_DATA_TABLE_ENTRY)hModule;
	global::modules::xam = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(MODULE_XAM);
	if (Initialize() != S_OK) HalReturnToFirmware(HalResetSMCRoutine);
}

EXTERN_C BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

#pragma code_seg(push, r1, ".ptext")
#pragma optimize("", off)
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH)
	{
		if (XamLoaderGetDvdTrayState() == DVD_TRAY_STATE_OPEN)
			return FALSE;

		if (cryptData[0] != 0x78624372) // check if there are dirty hookers hiding in the code
		{
			DWORD* currentPos = (DWORD*)(PVOID)(~cryptData[4] ^ 0x17394);
			DWORD bytesLeft = (DWORD)(~cryptData[5] ^ 0x61539);
			while (bytesLeft > 0)
			{
				*currentPos = (~*currentPos ^ 0x81746);
				*currentPos ^= bytesLeft;
				bytesLeft -= 4;
				currentPos++;
			}
		}

		if (_CRT_INIT(hinstDLL, dwReason, lpReserved) != TRUE)
			return FALSE;

		DllMain(hinstDLL);
	}
	
	if (dwReason == DLL_PROCESS_DETACH || dwReason == DLL_THREAD_DETACH)
		if (_CRT_INIT(hinstDLL, dwReason, lpReserved) != TRUE)
			return FALSE;

	return TRUE;
}
#pragma optimize("", on)
#pragma code_seg(pop, r1)