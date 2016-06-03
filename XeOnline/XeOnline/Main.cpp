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

	if (xbox::hypervisor::initialize() != S_OK)
		return E_FAIL;

	// disable some security shiz
	xbox::hypervisor::pokeDword(0x5B40, 0x38600000); // li r3, 0
	xbox::hypervisor::pokeDword(0x5B44, 0x4E800020); // blr

	if (xbox::keyvault::initialize() != S_OK)
	{
		xbox::utilities::log("Failed to set keyvault.");
		return E_FAIL;
	}

	if (xbox::hypervisor::setupCleanMemory() != S_OK)
		return E_FAIL;

	server::main::initialize();
	return S_OK;
}

VOID DllMain(HANDLE hModule)
{
	global::isDevkit = *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE;
	global::modules::client = (PLDR_DATA_TABLE_ENTRY)hModule;
	global::modules::xam = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(MODULE_XAM);
	if (Initialize() != S_OK) HalReturnToFirmware(HalResetSMCRoutine);
}

#pragma region Obfuscation
EXTERN_C BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

#pragma code_seg(push, r1, ".ptext")
#pragma optimize("", off)

void rc4_encryption(char* content, int content_length, char* key, int key_length)
{
	unsigned char S[256];
	unsigned int i = 0, j = 0, n = 0;
	unsigned char temp;

	for (i = 0;i < 256;i++)
	{
		S[i] = i;
	}
	for (i = j = 0;i < 256;i++)
	{
		j = (j + key[i % key_length] + S[i]) & 255;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
	}
	i = j = 0;

	for (n = 0; n < content_length; n++)
	{
		i = (i + 1) & 255;
		j = (j + S[i]) & 255;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;

		content[n] = content[n] ^ S[(S[i] + S[j]) & 255];
	}
}

BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH)
	{
		if (XamLoaderGetDvdTrayState() == DVD_TRAY_STATE_OPEN)
			return FALSE;

		if (global::cryptData[0] != 0x78624372) // check if there are dirty hookers hiding in the code
		{
			DWORD* currentPos = (DWORD*)(PVOID)(~global::cryptData[4] ^ 0x17394);
			DWORD bytesLeft = (DWORD)(~global::cryptData[5] ^ 0x61539);

			// decrypt code section
			while (bytesLeft > 0)
			{
				*currentPos = (~*currentPos ^ 0x81746);
				*currentPos ^= bytesLeft;
				bytesLeft -= 4;
				currentPos++;
			}

			// decrypt string data
			rc4_encryption((char*)(PVOID)(~global::cryptData[2] ^ 0x17394), ~global::cryptData[3] ^ 0x61539, (char*)global::cryptData, 8);
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
#pragma endregion