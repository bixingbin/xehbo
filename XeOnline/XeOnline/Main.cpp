#include "stdafx.h"

KEY_VAULT_DATA keyVault;
DWORD supportedVersion = 17489;
WCHAR wNotifyMsg[100];

BOOL isDevkit = FALSE;
BOOL isAuthed = FALSE;
BOOL hasChallenged = FALSE;

PLDR_DATA_TABLE_ENTRY hClient = NULL;
PLDR_DATA_TABLE_ENTRY hXam = NULL;

PVOID pSectionPatchData;
DWORD pSectionPatchDataSize;

PVOID pSectionHvcData;
DWORD pSectionHvcDataSize;


unsigned char call8EINit_Retail[28] = {
	0x38, 0x60, 0x00, 0x00, 0x48, 0x00, 0xB1, 0x2B, 0x3C, 0x60, 0xBE, 0xEF, 0x38, 0x21, 0x00, 0x10,
	0xE9, 0x81, 0xFF, 0xF8, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
};

unsigned char call8EInit_Devkit[28] = {
	0x38, 0x60, 0x00, 0x00, 0x48, 0x00, 0xAD, 0xA3, 0x3C, 0x60, 0xBE, 0xEF, 0x38, 0x21, 0x00, 0x10,
	0xE9, 0x81, 0xFF, 0xF8, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
};

QWORD __declspec(naked) HvxRunCode(DWORD Key, QWORD Type, QWORD Src, QWORD Dest, QWORD Size)
{
	__asm
	{
		li r0, 0x0
		sc
		blr
	}
}

HRESULT FixHVKeys()
{
	//DbgLog("Reinitializing hypervisor with new keyvault");

	PBYTE phybuf = (PBYTE)XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, MEM_LARGE_PAGES | PAGE_READWRITE | PAGE_NOCACHE);

	if (phybuf == NULL)
	{
		DbgLog("error allocating buffer!\n");
		HalReturnToFirmware(HalResetSMCRoutine);
	}

	ZeroMemory(phybuf, 0x1000);
	memcpy(phybuf, (isDevkit ? call8EInit_Devkit : call8EINit_Retail), sizeof(call8EINit_Retail));

	if (HvxRunCode(0x72627472, 4, 0xFE00, 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(phybuf), 7) == 0)
	{
		DbgLog("failed run code!");
		XPhysicalFree(phybuf);
		return ERROR_BAD_COMMAND;
	}

	XPhysicalFree(phybuf);

	DbgLog("reinitialized kv!");
	return ERROR_SUCCESS;
}

HRESULT setKeyVault()
{
	MemoryBuffer mbKv;
	MemoryBuffer mbCpu;

	if (!CReadFile(FILE_PATH_KV, mbKv))
		return E_FAIL;

	if (mbKv.GetDataLength() != 0x4000)
		return E_FAIL;

	CReadFile(FILE_PATH_CPUKEY, mbCpu);
	memcpy(keyVault.cpuKey, mbCpu.GetDataLength() == 0x10 ? mbCpu.GetData() : getCpuKey(), 0x10);
	XeCryptSha(keyVault.cpuKey, 0x10, NULL, NULL, NULL, NULL, keyVault.cpuKeyDigest, XECRYPT_SHA_DIGEST_SIZE);

	QWORD kvAddress = HvxPeekQWORD(isDevkit ? 0x00000002000162E0 : 0x0000000200016240);

	memcpy(&keyVault.Data, mbKv.GetData(), 0x4000);

	XECRYPT_HMACSHA_STATE hmacShaKv;
	XeCryptHmacShaInit(&hmacShaKv, keyVault.cpuKey, 0x10);
	XeCryptHmacShaUpdate(&hmacShaKv, (BYTE*)&keyVault.Data.OddFeatures, 0xD4);
	XeCryptHmacShaUpdate(&hmacShaKv, (BYTE*)&keyVault.Data.DvdKey, 0x1CF8);
	XeCryptHmacShaUpdate(&hmacShaKv, (BYTE*)&keyVault.Data.CardeaCertificate, 0x2108);
	XeCryptHmacShaFinal(&hmacShaKv, keyVault.kvDigest, XECRYPT_SHA_DIGEST_SIZE);

	if (!XeKeysPkcs1Verify(keyVault.kvDigest, keyVault.Data.KeyVaultSignature, (XECRYPT_RSA*)MasterKey))
		DbgLog("Warning: The cpu key provided is not for this keyvault.");
	
	SetMemory((PVOID)0x8E03A000, &keyVault.Data.ConsoleCertificate, 0x1A8);

	if (isDevkit) SetMemory((BYTE*)(GetPointer(0x81D6B198) + 0x30BC), &keyVault.Data.ConsoleCertificate, 0x1A8);

	SetMemory((PVOID)0x8E038020, &keyVault.Data.ConsoleCertificate.ConsoleId.abData, 5);

	BYTE newHash[XECRYPT_SHA_DIGEST_SIZE];
	XeCryptSha((BYTE*)0x8E038014, 0x3EC, NULL, NULL, NULL, NULL, newHash, XECRYPT_SHA_DIGEST_SIZE);
	SetMemory((PVOID)0x8E038000, newHash, XECRYPT_SHA_DIGEST_SIZE);

	HvxPeekBytes(kvAddress + 0xD0, &keyVault.Data.ConsoleObfuscationKey, 0x40);
	HvxPokeBytes(kvAddress, &keyVault.Data, 0x4000);

	return S_OK;
}

HRESULT Initialize()
{
	setLiveBlock(TRUE);
	wstring path(hClient->FullDllName.Buffer);
	path = path.substr(0, path.find_last_of(L"\\") + 1);
	if (CreateSymbolicLink(CONFIG_NAME_LINKER, (PCHAR)string(path.begin(), path.end()).c_str(), TRUE) != S_OK)
		return E_FAIL;
		
	if (XboxKrnlVersion->Build != supportedVersion && !isDevkit)
	{
		DbgLog("Error: Unsupported kernel version.");
		return E_FAIL;
	}

	if(!InitializeHooks())
		return E_FAIL;

	if (!XGetModuleSection(hClient, isDevkit ? "DEVKITP" : "RETAILP", &pSectionPatchData, &pSectionPatchDataSize))
		return E_FAIL;

	if (!XGetModuleSection(hClient, "HVC", &pSectionHvcData, &pSectionHvcDataSize))
		return E_FAIL;

	if (ApplyPatches(NULL, pSectionPatchData) == 0)
		return E_FAIL;

	if (setKeyVault() != S_OK)
	{
		DbgLog("Error: Failed to set keyvault.");
		return E_FAIL;
	}

	BYTE currentMacAddress[6];
	BYTE spoofedMacAddress[6] = {
		0xFF, 0xFF, 0xFF,
		keyVault.Data.ConsoleCertificate.ConsoleId.asBits.MacIndex3,
		keyVault.Data.ConsoleCertificate.ConsoleId.asBits.MacIndex4,
		keyVault.Data.ConsoleCertificate.ConsoleId.asBits.MacIndex5
	};

	if ((XboxHardwareInfo->Flags & 0xF0000000) > 0x40000000)
	{
		spoofedMacAddress[0] = 0x7C;
		spoofedMacAddress[1] = 0xED;
		spoofedMacAddress[2] = 0x8D;
	}
	else
	{
		spoofedMacAddress[0] = 0x00;
		spoofedMacAddress[1] = 0x22;
		spoofedMacAddress[2] = 0x48;
	}

	if (NT_SUCCESS(ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, currentMacAddress, 6, NULL)))
		if (memcmp(currentMacAddress, spoofedMacAddress, 6) != 0)
			if (NT_SUCCESS(ExSetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, spoofedMacAddress, 6)))
				HalReturnToFirmware(HalFatalErrorRebootRoutine);

	DWORD temp = 0;
	XeCryptSha(spoofedMacAddress, 6, NULL, NULL, NULL, NULL, (BYTE*)&temp, 4);
	setupSpecialValues(temp & ~0xFF);
	XamCacheReset(XAM_CACHE_ALL);

	FixHVKeys();

	HANDLE hThread;
	DWORD dwThreadId;
	ExCreateThread(&hThread, 0, &dwThreadId, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)ServerUpdatePresenceThread, 0, EX_CREATE_FLAG_SYSTEM | EX_CREATE_FLAG_SUSPENDED);
	XSetThreadProcessor(hThread, 2);
	SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
	ResumeThread(hThread);
	CloseHandle(hThread);
	
	return S_OK;
}

DWORD cryptData[6] = { 0x78624372, 0x7970746F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF }; // KEY | ADDRESS | SIZE | ADDRESS | SIZE

VOID DllMain(HANDLE hModule)
{
	// decrypt the strings (calling it here so they cant see we use XeCryptRc4)
	if (cryptData[0] != 0x78624372)
		XeCryptRc4((PBYTE)cryptData, 8, (PBYTE)(PVOID)(~cryptData[2] ^ 0x17394), ~cryptData[3] ^ 0x61539);

	hClient = (PLDR_DATA_TABLE_ENTRY)hModule;
	hXam = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(MODULE_XAM);
	isDevkit = *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE;
	if (XamLoaderGetDvdTrayState() == DVD_TRAY_STATE_OPEN) setLiveBlock(TRUE);
	else if (Initialize() != ERROR_SUCCESS) HalReturnToFirmware(HalResetSMCRoutine);
}

EXTERN_C BOOL WINAPI _CRT_INIT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

#pragma code_seg(push, r1, ".ptext")
#pragma optimize("", off)
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH)
	{
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