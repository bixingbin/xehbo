#include "stdafx.h"
#include "Config.h"
#include "Utilities.h"
#include "TitleHooks.h"
#include "SystemHooks.h"
#include "ServComm.h"
#include "HUD.h"

#if defined(GHOSTS_PUBLIC_CHEATER) || defined(AW_PUBLIC_CHEATER)
#include "Ghosts.h"
#endif

XECRYPT_SHA_STATE xShaCurrentXex;
extern PLDR_DATA_TABLE_ENTRY hXam;


HANDLE hGhosts;

DWORD spAddressGhosts;
DWORD mpAddressGhosts;
extern BOOL isDevkit;
DWORD spAddressAW;
DWORD mpAddressAW;
DWORD spPatch1AW;
DWORD spPatch2AW;
DWORD spPatch3AW;
DWORD spPatch4AW;
DWORD mpPatch1AW;
DWORD mpPatch2AW;
DWORD mpPatch3AW;
DWORD mpPatch4AW;
DWORD mpPatchAWNew;
DWORD mpPatch1Ghosts;
DWORD mpPatch2Ghosts;
DWORD mpPatch3Ghosts;
DWORD mpPatch4Ghosts;
DWORD mpPatch5Ghosts;
DWORD spPatch1Ghosts;
DWORD spPatch2Ghosts;
DWORD spPatch3Ghosts;
DWORD spBO2Patch1;
DWORD spPatch1BO2;
DWORD spPatch2BO2;
DWORD spPatch3BO2;
DWORD spPatch4BO2;
DWORD mpBO2Patch1;
DWORD mpPatch1BO2;
DWORD mpPatch2BO2;
DWORD mpPatch3BO2;
DWORD mpPatch4BO2;
DWORD mpPatch5BO2;

//extern ORDINALS* ordinals;
extern QWORD qwRandomMachineID;
extern BYTE bRandomMacAddress[];
extern CHAR cRandomConsoleSerialNumber[];
extern CHAR cRandomConsoleID[];
extern DWORD dwChalLength1;
extern DWORD dwChalLength2;

//extern int applyPatchData(DWORD* patchData);

static QWORD RandomMachineID;
static BYTE RandomMacAddress[6];
static char RandomConsoleSerialNumber[12];
static char RandomConsoleID[12];

//DWORD ServerGetSecurityAuth(DWORD offsetIndexReq);

DWORD GetModuleImportCallAddress(LDR_DATA_TABLE_ENTRY* moduleHandle, CHAR* ImportedModuleName, DWORD Ordinal)
{
	DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
	if (address == NULL)
		return S_FALSE;

	// Get our header field from this module
	VOID* headerBase = moduleHandle->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
	if (importDesc == NULL)
		return S_FALSE;

	// Our result
	DWORD result = 2; // No occurances found

					  // Get our string table position
	CHAR* stringTable = (CHAR*)(importDesc + 1);

	// Get our first entry
	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

	// Loop through our table
	for (DWORD x = 0; x < importDesc->ModuleCount; x++)
	{
		// Go through and search all addresses for something that links
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++)
		{
			// Check the address of this import
			DWORD value = *((DWORD*)importAdd[y]);
			if (value == address)
			{
				if (result != 2)
				{
					HalReturnToFirmware(HalPowerDownRoutine);
					return S_FALSE;
				}

				// We found a matching address address
				result = importAdd[y + 1];
			}
		}

		// Goto the next table
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}

	// Return our result
	return result;
}


char GenerateRandomNumericalCharacter()
{
	// Create our character array
	char Characters[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

	// Get our random number from 0-9
	DWORD dwRandom = rand() % 9;

	// Return our random number as a character
	return Characters[dwRandom];
}

VOID GenerateRandomValues(PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	// Generate random machine id
	BYTE* MachineID = (BYTE*)XPhysicalAlloc(8, MAXULONG_PTR, NULL, PAGE_READWRITE);
	if (MachineID == NULL)
	{
		DbgPrint("error allocating buffer!");
		HalReturnToFirmware(HalResetSMCRoutine);
	}
	MachineID[0] = 0xFA;
	MachineID[1] = 0x00;
	MachineID[2] = 0x00;
	MachineID[3] = 0x00;
	XeCryptRandom((BYTE*)(MachineID + 4), 4);
	SetMemory(&RandomMachineID, MachineID, 8);
	XPhysicalFree(MachineID);

	// Generate random mac address
	if ((XboxHardwareInfo->Flags & 0xF0000000) > 0x40000000){
		RandomMacAddress[0] = 0x7C;
		RandomMacAddress[1] = 0xED;
		RandomMacAddress[2] = 0x8D;
	}
	else{
		RandomMacAddress[0] = 0x00;
		RandomMacAddress[1] = 0x22;
		RandomMacAddress[2] = 0x48;
	}
	XeCryptRandom((BYTE*)(RandomMacAddress + 3), 3);

	// Use this to randomize MI
	BYTE* RandomBytes = (BYTE*)XPhysicalAlloc(16, MAXULONG_PTR, NULL, PAGE_READWRITE);
	if (RandomBytes == NULL)
	{
		DbgPrint("error allocating buffer!\n");
		HalReturnToFirmware(HalResetSMCRoutine);
	}
	XeCryptRandom(RandomBytes, 16);
	SetMemory((LPVOID)GetModuleImportCallAddress(ModuleHandle, MODULE_XAM, 0x2D9), RandomBytes, 16);
	XPhysicalFree(RandomBytes);

	// Generate random console serial number
	for (int i = 0; i < 12; i++)
	{
		RandomConsoleSerialNumber[i] = GenerateRandomNumericalCharacter();
	}

	// Generate random console id
	for (int i = 0; i < 12; i++)
	{
		RandomConsoleID[i] = GenerateRandomNumericalCharacter();
	}
}

DWORD NetDll_XNetXnAddrToMachineIdHook(XNCALLER_TYPE xnc, const XNADDR* pxnaddr, QWORD* pqwMachineId)
{
	*pqwMachineId = RandomMachineID;
	//DbgPrint("NetDll_XNetXnAddrToMachineIdHook spoofed."); would crash on Ghosts
	return ERROR_SUCCESS;
}

DWORD NetDll_XNetGetTitleXnAddrHook(XNCALLER_TYPE xnc, XNADDR *pxna)
{
	DWORD retVal = NetDll_XNetGetTitleXnAddr(XNCALLER_TITLE, pxna);

	XNADDR ourAddr;

	XNetGetTitleXnAddr(&ourAddr);
	if (memcmp(&ourAddr, pxna, sizeof(XNADDR) == 0))
	{
		SetMemory((BYTE*)pxna->abEnet, RandomMacAddress, 6);
	}

	//DbgPrint("NetDll_XNetGetTitleXnAddrHook spoofed."); would crash on Ghosts
	return retVal;
}

DWORD XeKeysGetConsoleIDHook(PBYTE databuffer, char* szBuffer)
{
	if (databuffer != 0) SetMemory(databuffer, RandomConsoleID, 0xC);
	if (szBuffer != 0) SetMemory(szBuffer, RandomConsoleID, 0xC);
	//DbgPrint("XeKeysGetConsoleIDHook spoofed."); would crash on Ghosts

	return ERROR_SUCCESS;
}

DWORD XeKeysGetKeyHook(WORD KeyId, PVOID KeyBuffer, PDWORD KeyLength)
{
	if (KeyId == 0x14)
	{
		SetMemory(KeyBuffer, RandomConsoleSerialNumber, 0xC);
		//DbgPrint("XeKeysGetKey spoofed."); would crash on Ghosts
		return ERROR_SUCCESS;
	}
	
	return XeKeysGetKey(KeyId, KeyBuffer, KeyLength);
}

__declspec(naked) INT AnswerChallenges(__int64 r3, __int64 r4, DWORD ChallengeResponse) //SaveStub Used for answerChallengeHook
{
	__asm
	{
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}

VOID AnswerChallengesHook(__int64 r3, __int64 r4, DWORD dwChallengeResponse) //This is the actual hook it self, setting the security flag in the response.
{
	// Setup our structure
	//PCOD_CHAL_RESP ChallengeResponse = (PCOD_CHAL_RESP)(dwChallengeResponse + 0x22);
#if defined(SHOWFLAGS)
	DbgPrint("AW Security Flag = 0x%02X\n", ChallengeResponse->bSecurityFlag);
#endif
	// Spoof our security flag
	//ChallengeResponse->bSecurityFlag = 0x0B; // The right flag is 0x0B on AW
#if defined(SHOWFLAGS)
	DbgPrint("Spoofed Flag = 0x%02X\n", ChallengeResponse->bSecurityFlag);
#endif
	AnswerChallenges(r3, r4, dwChallengeResponse);
}

VOID GhostsChallengesHook(__int64 r3, __int64 r4, DWORD dwChallengeResponse)
{
	// Setup our structure
	//PCOD_CHAL_RESP ChallengeResponse = (PCOD_CHAL_RESP)(dwChallengeResponse + 0x1E);
#if defined(SHOWFLAGS)
	DbgPrint("Ghosts Security Flag = 0x%02X\n", ChallengeResponse->bSecurityFlag);
#endif
	// Spoof our security flag
	//ChallengeResponse->bSecurityFlag = 0x0F; // The right flag is 0x0F on Ghosts
#if defined(SHOWFLAGS)
	DbgPrint("Spoofed Flag = 0x%02X\n", ChallengeResponse->bSecurityFlag);
#endif
	AnswerChallenges(r3, r4, dwChallengeResponse);
}

DWORD XexGetModuleHandleHook(PSZ moduleName, PHANDLE hand)
{
	if (moduleName != NULL) // <-- BO2 throws us a null module name to cause a crash, kinda cute
	{
		char buff[4];
		memcpy(buff, moduleName, 4);
		if (memcmp(buff, "xbdm", 4) == 0)
		{
			*hand = 0;
			return 0xC0000225; // Module not found
		}
	}
	return XexGetModuleHandle(moduleName, hand);
}

DWORD XexGetModuleHandleHookGhosts(PSZ moduleName, PHANDLE hand)
{
	if (moduleName != NULL)
	{
		// logic to switch flag between 0xF and 0xB: put here because the memory value isn't initialized immediately
		DWORD dwPatchData = 0x38600000; // li %r3, 0
		dwPatchData |= *(DWORD*)0x8418B628; // this address is either zero'd or 00000002, allowing us to switch the flags as needed
		SetMemory((LPVOID)mpPatch5Ghosts, &dwPatchData, sizeof(DWORD));

		char buff[4];
		memcpy(buff, moduleName, 4);
		if (memcmp(buff, "xbdm", 4) == 0)
		{
			*hand = NULL;
			return 0xC0000225; // Module not found
		}
	}

	return XexGetModuleHandle(moduleName, hand);
}

DWORD XSecurityCreateProcessHook(DWORD dwHardwareThread)
{
	return ERROR_SUCCESS;
}

VOID XSecurityCloseProcessHook() {}

static DWORD dwNumCIV = 0;

VOID __cdecl APCWorker(void* Arg1, void* Arg2, void* Arg3)
{
	// Call our completion routine if we have one
	if (Arg2)
	{
		((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
	}
	dwNumCIV ++;
}

DWORD XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	// Queue our completion routine
	if (lpCompletionRoutine)
	{
		NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);
	}

	// All done
	return ERROR_SUCCESS;
}

DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation)
{
	if (pFailureInformation->dwSize != 0x18) {
		dwNumCIV = 0;
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	pFailureInformation->dwBlocksChecked = dwNumCIV;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = dwNumCIV;
	pFailureInformation->fComplete = TRUE;
	return ERROR_SUCCESS;
}

DWORD XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress)
{
	// Check our module handle
	if (hand == hXam)
	{
		switch (dwOrdinal)
		{
			case 0x9BB:
				*pvAddress = XSecurityCreateProcessHook;
				return 0;
			case 0x9BC:
				*pvAddress = XSecurityCloseProcessHook;
				return 0;
			case 0x9BD:
				*pvAddress = XSecurityVerifyHook;
				return 0;
			case 0x9BE:
				*pvAddress = XSecurityGetFailureInfoHook;
				return 0;
		}
	}

	// Call our real function if we aren't interested
	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

static DWORD valueToSpoof = 0x42FB0000; // Our obfuscator removes the reference to this, all good

QWORD inline __declspec (naked) tits(void)
{
	__asm
	{
		lau		r10, valueToSpoof;
		lal		r8, r10, valueToSpoof;
	}
}

VOID InitializeBlackOps2Hooks(XEX_EXECUTION_ID* pExecutionId, PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	BOOL ShouldContinue = (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0 || wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0);
	if (!ShouldContinue)
	{
		DbgPrint("We don't want to accidently patch something not in the correct module, aborting");
		return;
	}

	DWORD TUv = 18; // BO2 TU Version
	DWORD dwVersion = (pExecutionId->Version >> 8) & 0xFF;

	if (dwVersion != TUv)
	{
		DbgPrint("TU != %d", TUv);
		if (dwVersion > TUv) HalReturnToFirmware(HalFatalErrorRebootRoutine); // Could maybe send to dash here instead of a reboot
		return;
	}

	// Generate our values
	GenerateRandomValues(ModuleHandle);

	// Apply our bypass
	PatchModuleImport(ModuleHandle, MODULE_XAM, 64, (DWORD)NetDll_XNetXnAddrToMachineIdHook);
	PatchModuleImport(ModuleHandle, MODULE_XAM, 73, (DWORD)NetDll_XNetGetTitleXnAddrHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 405, (DWORD)XexGetModuleHandleHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 580, (DWORD)XeKeysGetKeyHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 582, (DWORD)XeKeysGetConsoleIDHook);

	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
	{
		DWORD nop = 0x60000000;
		DWORD dwPatchData = 0x38600000;
		SetMemory((LPVOID)mpPatch5BO2, &nop, 4); // Disables CRC32_Split hash

		// Patching the debug port value
		/*Dword dwPatchData = mpBO2Patch1; //Confuse people on the patch we do
		SetMemory((LPVOID)mpPatch1BO2, &dwPatchData, sizeof(DWORD));

		dwPatchData = ((DWORD)tits);
		dwPatchData += 4;

		// Patching the value that BO2 grabs to our clean one
		SetMemory((LPVOID)mpPatch2BO2, ((LPVOID*)tits), sizeof(DWORD)0;
		SetMemory((LPVOID)mpPatch3BO2, (LPVOID*)dwPatchData, sizeof(DWORD));*/

		// Fix freezing error for devkits
		if (isDevkit)
		{
			nop = 0x48000018;
			SetMemory((LPVOID)mpPatch4BO2, &nop, sizeof(DWORD)); // Didn't need to hide this, but it would have stuck out like a sore thumb that we were doing something fishy
		}
	}

	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
	{
		// SP
		DWORD nop = 0x60000000;
		// Bypass 2 - Unbannable for 2 weeks and counting
		SetMemory((LPVOID)spPatch4BO2, &nop, 4); // Disables CRC32_Split hash

		// Patching the debug port value
		/*Dword dwPatchData = spBO2Patch1; //Confuse people on the patch we do
		SetMemory((LPVOID)spPatch1BO2, &dwPatchData, sizeof(DWORD));

		dwPatchData = ((DWORD)tits);
		dwPatchData += 4;

		// Patching the value that BO2 grabs to our clean one
		SetMemory((LPVOID)spPatch2BO2, ((LPVOID*)tits), sizeof(DWORD)0;
		SetMemory((LPVOID)spPatch3BO2, (LPVOID*)dwPatchData, sizeof(DWORD));*/
	}

}

VOID InitializeGhostsHooks(XEX_EXECUTION_ID* pExecutionId, PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	BOOL ShouldContinue = wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0 || wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0;
	if (!ShouldContinue)
	{
		DbgPrint("We don't want to accidently patch something not in the correct module, aborting.");
		return;
	}

	DWORD TUv = 17; // Ghosts TU Version
	DWORD dwVersion = (pExecutionId->Version >> 8) & 0xFF;

	if (dwVersion != TUv)
	{
		DbgPrint("TU != %d", TUv);
		if (dwVersion > TUv) HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return;
	}

	// Generate our values
	GenerateRandomValues(ModuleHandle);

	// Apply our bypass
	//PatchModuleImport(ModuleHandle, NAME_XAM, 64, (DWORD)NetDll_XNetXnAddrToMachineIdHook);
	//PatchModuleImport(ModuleHandle, NAME_XAM, 73, (DWORD)NetDll_XNetGetTitleXnAddrHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 405, (DWORD)XexGetModuleHandleHookGhosts);
	//PatchModuleImport(ModuleHandle, NAME_KERNEL, 580, (DWORD)XeKeysGetKeyHook);
	//PatchModuleImport(ModuleHandle, NAME_KERNEL, 582, (DWORD)XeKeysGetConsoleIDHook);

	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
	{
		// This is specific to multiplayer
		PatchModuleImport(ModuleHandle, MODULE_KERNEL, 405, (DWORD)XexGetModuleHandleHookGhosts);

		DWORD dwPatchData = 0x39200009; // li %r9, 9
		SetMemory((LPVOID)mpPatch1Ghosts, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x48000010; // b cr6, 0x10
		SetMemory((LPVOID)mpPatch2Ghosts, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x38600000; // li %r3, 0
		SetMemory((LPVOID)mpPatch3Ghosts, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x39600001; // li %r11, 1
		SetMemory((LPVOID)mpPatch4Ghosts, &dwPatchData, sizeof(DWORD));

#if defined (GHOSTS_PUBLIC_CHEATER)
		if (!DisableGhostsPublicCheater)
		{
			InitializeGhostsPublicCheater();
		}

#endif
	}
	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
	{
		PatchModuleImport(ModuleHandle, MODULE_KERNEL, 405, (DWORD)XexGetModuleHandleHook);

		DWORD dwPatchData = 0x48000010; // b cr6, 0x10
		SetMemory((LPVOID)spPatch1Ghosts, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x38600000; // li %r3, 0
		SetMemory((LPVOID)spPatch2Ghosts, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x39600001; // li %r11, 1
		SetMemory((LPVOID)spPatch3Ghosts, &dwPatchData, sizeof(DWORD));
	}
}


VOID InitializeAWHooks(XEX_EXECUTION_ID* pExecutionId, PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	BOOL ShouldContinue = wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0 || wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0;
	if (!ShouldContinue)
	{
		DbgPrint("We don't want to accidently patch something not in the correct module, aborting.");
		return;
	}

	DWORD TUv = 17; // AW TU VERSION
	DWORD dwVersion = (pExecutionId->Version >> 8) & 0xFF;

	if (dwVersion != TUv)
	{
		DbgPrint("TU != %d", TUv);
		if (dwVersion > TUv) HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return;
	}

	// Generate our values
	GenerateRandomValues(ModuleHandle);

	// Apply our bypasses
	PatchModuleImport(ModuleHandle, MODULE_XAM, 64, (DWORD)NetDll_XNetXnAddrToMachineIdHook);
	PatchModuleImport(ModuleHandle, MODULE_XAM, 73, (DWORD)NetDll_XNetGetTitleXnAddrHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 405, (DWORD)XexGetModuleHandleHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 580, (DWORD)XeKeysGetKeyHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 582, (DWORD)XeKeysGetConsoleIDHook);

	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0)
	{
		DWORD dwPatchData = 0x60000000;

		dwPatchData = 0x39600000; // li %r11, 9
		SetMemory((LPVOID)mpPatch1AW, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x48000010; // b 0x10
		SetMemory((LPVOID)mpPatch2AW, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x38600000; // li %r3, 0
		SetMemory((LPVOID)mpPatch3AW, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x39600001; // li %r11, 1
		SetMemory((LPVOID)mpPatch4AW, &dwPatchData, sizeof(DWORD));

#if defined (AW_PUBLIC_CHEATER)
		if (!DisableAwPublicCheater)
		{
			InitializeAdvancedWarfarePublicCheater();
		}
#endif
	}
	else if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
	{
		DWORD dwPatchData = 0x48000010; // nop
		SetMemory((LPVOID)spPatch1AW, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x60000000; // li %r3, 0
		SetMemory((LPVOID)spPatch2AW, &dwPatchData, sizeof(DWORD));
		dwPatchData = 0x39600001; // li %r11, 1
		SetMemory((LPVOID)spPatch3AW, &dwPatchData, sizeof(DWORD));
	}
}

VOID InitializeDestinyHooks(XEX_EXECUTION_ID* pExecutionId, PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	/*if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0)
	{
		DWORD dwPatchData = 0x38600000;
		memcpy((LPVOID)0x8311E1E8, &dwPatchData, 4);
		dwPatchData = 0x4E800020;
		memcpy((LPVOID)0x8311E1EC, &dwPatchData, 4);
		dwPatchData = 0x60000000;
		memcpy((LPVOID)0x8278DFF0, &dwPatchData, 4);
	}*/
}

VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	XEX_EXECUTION_ID* pExecutionId;
	if (XamGetExecutionId(&pExecutionId) != S_OK) return;

	//Challenge.pCurrentExecutionId = pExecutionId;
	if (pExecutionId->TitleID != 0xFFFE07D1)
	{
		PLDR_DATA_TABLE_ENTRY ldat = (PLDR_DATA_TABLE_ENTRY)ModuleHandle;
		PIMAGE_XEX_HEADER xhead = (PIMAGE_XEX_HEADER)ldat->XexHeaderBase;

		BYTE* btmp = (BYTE*)(xhead->SecurityInfo + 0x17C);
		DWORD arg1len = xhead->SizeOfHeaders - ((DWORD)btmp - (DWORD)xhead); // header size - offset into header
		XeCryptShaInit(&xShaCurrentXex);
		XeCryptShaUpdate(&xShaCurrentXex, btmp, arg1len);
	}

	// Hook any calls to XexGetProcedureAddress
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);

	// If this module tries to load more modules, this will let us get those as well
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook);

	dwNumCIV = 0;

	// Reset ordinals
	//memset((PVOID)ordinals, 0, sizeof(ORDINALS));

#ifdef CUSTOM_HUD
	//HUD hook for adding menu button (only for retail right now..)
	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"hud.xex") == 0 && !CleanMode /*&& !isDevkit*/)
	{
		// These are hud specific hooks
		if (S_OK == PatchModuleImport(ModuleHandle, MODULE_XAM, 855, (DWORD)XuiSceneCreateHook))
		{
			DbgPrint("Hooked: 'HUD: XuiSceneCreate'");
		}
		if (S_OK == PatchModuleImport(ModuleHandle, MODULE_XAM, 842, (DWORD)XuiRegisterClassHook))
		{
			DbgPrint("Hooked: 'HUD: XuiRegisterClass'");
		}
		if (S_OK == PatchModuleImport(ModuleHandle, MODULE_XAM, 866, (DWORD)XuiUnregisterClassHook))
		{
			DbgPrint("Hooked: 'HUD: XuiUnregisterClass'");
		}
	}
	else
#endif

#ifdef SPOOF_MS_POINTS
		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"Guide.MP.Purchase.xex") == 0) {
			DbgPrint("Applied MS Points spoof patches");
			ApplyPatches(NULL, isDevkit ? PATCH_DATA_MPPURCHASE_MSPOINTS_DEVKIT : PATCH_DATA_MPPURCHASE_MSPOINTS_RETAIL);
		}
#endif
#ifdef TITLE_HAX
	switch (pExecutionId->TitleID)
	{
		case COD_BLACK_OPS_2:
		{
			InitializeBlackOps2Hooks(pExecutionId, ModuleHandle);
			break;
		}
		case COD_GHOSTS:
		{
			InitializeGhostsHooks(pExecutionId, ModuleHandle);
			break;
		}
		case COD_AW:
		{
			InitializeAWHooks(pExecutionId, ModuleHandle);
			break;
		}
		//case DESTINY:
		//{
		//	InitializeDestinyHooks(pExecutionId, ModuleHandle);
		//	break;
		//}
		default:
		{
			break;
		}
	}
#endif
}