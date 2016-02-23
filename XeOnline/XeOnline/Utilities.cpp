#include "stdafx.h"

extern BOOL isDevkit;
extern WCHAR wNotifyMsg[100];
extern PLDR_DATA_TABLE_ENTRY hClient;

VOID DbgLog(const CHAR* strFormat, ...)
{
	CHAR buffer[1000];

	va_list pArgList;
	va_start(pArgList, strFormat);
	vsprintf_s(buffer, 1000, strFormat, pArgList);
	va_end(pArgList);

	printf("[XeOnline] %s\n", buffer);

	ofstream writeLog;
	writeLog.open(FILE_PATH_LOG, ofstream::app);
	if (writeLog.is_open())
	{
		writeLog.write(buffer, strlen(buffer));
		writeLog.write("\n", 1);
	}
	writeLog.close();
}

HRESULT XZPGetFile(LPCWSTR szFile, CONST BYTE **pSectionData, DWORD* pSectionSize)
{
	WCHAR szLocator[80];
	XamBuildResourceLocator(hClient, L"xeonline", szFile, szLocator, 80);

	HXUIRESOURCE hResource = 0;
	BOOL bIsMemoryResource = FALSE;

	if (XuiResourceOpen(szLocator, &hResource, &bIsMemoryResource) != S_OK)
		return E_FAIL;

	if (bIsMemoryResource)
	{
		XuiResourceGetBuffer(hResource, pSectionData);
		*pSectionSize = XuiResourceGetTotalSize(hResource);
		XuiResourceClose(hResource);
		return S_OK;
	}

	return E_FAIL;
}

PBYTE getCpuKey()
{
	BYTE fuseCpu[0x10];
	BYTE hvCpu[0x10];

	HvxPeekBytes(0x20, hvCpu, 0x10);
	*(QWORD*)(fuseCpu) = HvxPeekQWORD(0x8000020000020000 + (3 * 0x200));
	*(QWORD*)(fuseCpu + 8) = HvxPeekQWORD(0x8000020000020000 + (5 * 0x200));

	if (memcmp(fuseCpu, hvCpu, 0x10) != 0)
		VdDisplayFatalError(69);

	return fuseCpu;
}
//DWORD originalDns[7];
//PCHAR fakeDnsAddress = "NULL.%sXBOXLIVE.COM"; 
HRESULT setLiveBlock(BOOL enable)
{
	DWORD value = enable ? 1 : 0;

	if (isDevkit)
	{
		if (enable) *(DWORD*)0x8161DDD4 = 0x4E554C4C;
		else *(DWORD*)0x8161DDD4 = 0x50524F44;

		//if (enable)
		//{
		//	SetMemory(originalDns, (PVOID)0x8161DDD8, sizeof(originalDns));
		//	DWORD fakePtr = (DWORD)fakeDnsAddress;

		//	for (DWORD i = 0; i < sizeof(originalDns) / 4; i++)
		//	{
		//		DWORD address = (0x8161DDD8 + (i * 4));
		//		printf("address = 0x%X\n", address);
		//		SetMemory((PVOID)address, &fakePtr, 4);
		//	}
		//}
		//else SetMemory((PVOID)0x8161DDD8, originalDns, sizeof(originalDns));

		return S_OK;
	}

	if (!dlaunchSetOptValByName)dlaunchSetOptValByName = (DLAUNCHSETOPTVALBYNAME)ResolveFunction("launch.xex", DL_ORDINALS_SETOPTVALBYNAME);
	if (!dlaunchGetOptValByName)dlaunchGetOptValByName = (DLAUNCHGETOPTVALBYNAME)ResolveFunction("launch.xex", DL_ORDINALS_GETOPTVALBYNAME);

	// set liveblock
	if (!dlaunchSetOptValByName("liveblock", &value))
		return E_FAIL;

	// set stronglive
	if (!dlaunchSetOptValByName("livestrong", &value))
		return E_FAIL;

	return S_OK;
}

VOID setNotifyMsg(WCHAR* msg)
{
	wcsncpy(wNotifyMsg, msg, sizeof(wNotifyMsg) / sizeof(WCHAR));
}

BOOL isNotifyMsgSet()
{
	return (wNotifyMsg[0] != 0 && wNotifyMsg[1] != 0);
}

VOID doErrShutdown(WCHAR* msg, BOOL reboot)
{
	XNotifyUI(msg);
	Sleep(7000);
	HalReturnToFirmware(reboot ? HalFatalErrorRebootRoutine : HalResetSMCRoutine);
}

VOID printBytes(PBYTE bytes, DWORD len)
{
	for (int i = 0; i<(int)len; i++)
	{
		if (i % 16 == 0 && i != 0)
			DbgPrint("\n");

		DbgPrint("%02X", bytes[i]);
	}
	DbgPrint("\n");
}

BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa)
{
	BYTE scratch[256];
	DWORD val = pRsa->cqw << 3;
	if (val <= 0x200)
	{
		XeCryptBnQw_SwapDwQwLeBe((QWORD*)pbSig, (QWORD*)scratch, val >> 3);
		if (XeCryptBnQwNeRsaPubCrypt((QWORD*)scratch, (QWORD*)scratch, pRsa) == 0) return FALSE;
		XeCryptBnQw_SwapDwQwLeBe((QWORD*)scratch, (QWORD*)scratch, val >> 3);
		return XeCryptBnDwLePkcs1Verify((const PBYTE)pbHash, scratch, val);
	}
	else return FALSE;
}

VOID PatchInJump(DWORD* Address, DWORD Destination, BOOL Linked)
{
	Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
	if(Destination & 0x8000) Address[0] += 1;
	Address[1] = 0x396B0000 + (Destination & 0xFFFF);
	Address[2] = 0x7D6903A6;
	Address[3] = Linked ? 0x4E800421 : 0x4E800420;
}

VOID PatchInBranch(DWORD* Address, DWORD Destination, BOOL Linked)
{
	Address[0] = (0x48000000 + ((Destination - (DWORD)Address) & 0x3FFFFFF) | Linked);
}

DWORD makeBranch(DWORD branchAddr, DWORD destination, BOOL linked)
{
	return 0x48000000 | ((destination - branchAddr) & 0x03FFFFFF) | linked;
}

FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal)
{
	HMODULE mHandle = GetModuleHandle(ModuleName);
	return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
}

DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress)
{
	LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(Module);
	return (moduleHandle == NULL) ? S_FALSE : PatchModuleImport(moduleHandle, ImportedModuleName, Ordinal, PatchAddress);
}

DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress)
{
	// First resolve this imports address
	DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
	if(address == NULL)
		return S_FALSE;

	// Get our header field from this module
	VOID* headerBase = Module->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
	if(importDesc == NULL)
		return S_FALSE;

	// Our result
	DWORD result = 2; // No occurances patched

	// Get our string table position
	CHAR* stringTable = (CHAR*)(importDesc + 1);
	
	// Get our first entry
	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

	// Loop through our table
	for(DWORD x = 0; x < importDesc->ModuleCount; x++) {
		
		// Go through and search all addresses for something that links
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for(DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {

			// Check the address of this import
			DWORD value = *((DWORD*)importAdd[y]);
			if(value == address) {

				// We found a matching address address
				SetMemory((DWORD*)importAdd[y], &PatchAddress, 4);
				DWORD newCode[4];
				PatchInJump(newCode, PatchAddress, FALSE);
				SetMemory((DWORD*)importAdd[y + 1], newCode, 16);

				// We patched at least one occurence
				result = S_OK;
			}
		}

		// Goto the next table
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}

	// Return our result
	return result;
}

VOID __declspec(naked) GLPR_FUN(VOID)
{
	__asm{
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD relinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr)
{
	DWORD saver[0x30];

	SetMemory(saver, GLPR_FUN, 0x30 * 4);

	DWORD inst = 0, repl = 0;

	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if (offset & 0x2000000)
		offset = offset | 0xFC000000;

	SetMemory(&repl, &orgAddr[((DWORD)offset) / 4], 4);

	for (int i = 0; i < 20; i++)
	{
		if (repl == saver[i])
		{
			int newOffset = (int)((PDWORD)(GLPR_FUN)+(DWORD)i) - (int)saveStubAddr;
			inst = 0x48000001 | (newOffset & 0x3FFFFFC);
		}
	}

	return inst;
}

VOID HookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest)
{
	if ((saveStub != NULL) && (addr != NULL))
	{
		int i;
		DWORD addrReloc = (DWORD)(&addr[4]);// replacing 4 instructions with a jump, this is the stub return address
											//DbgPrint("hooking addr: %08x savestub: %08x dest: %08x addreloc: %08x\n", addr, saveStub, dest, addrReloc);
											// build the stub
											// make a jump to go to the original function start+4 instructions
		DWORD writeBuffer;
		if (addrReloc & 0x8000) // If bit 16 is 1
			writeBuffer = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + 1); // lis %r11, dest>>16 + 1
		else
			writeBuffer = 0x3D600000 + ((addrReloc >> 16) & 0xFFFF); // lis %r11, dest>>16

		SetMemory(&saveStub[0], &writeBuffer, 4);
		writeBuffer = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
		SetMemory(&saveStub[1], &writeBuffer, 4);
		writeBuffer = 0x7D6903A6; // mtctr %r11
		SetMemory(&saveStub[2], &writeBuffer, 4);

		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		for (i = 0; i<4; i++)
		{
			if ((addr[i] & 0x48000003) == 0x48000001) // branch with link
			{
				//DbgPrint("relink %08x\n", addr[i]);
				writeBuffer = relinkGPLR((addr[i] & ~0x48000003), &saveStub[i + 3], &addr[i]);
				SetMemory(&saveStub[i + 3], &writeBuffer, 4);
			}
			else
			{
				//DbgPrint("copy %08x\n", addr[i]);
				writeBuffer = addr[i];
				SetMemory(&saveStub[i + 3], &writeBuffer, 4);
			}
		}
		writeBuffer = 0x4E800420; // bctr
		SetMemory(&saveStub[7], &writeBuffer, 4);
		__dcbst(0, saveStub);
		__sync();
		__isync();

		//DbgPrint("savestub:\n");
		//for(i = 0; i < 8; i++)
		//{
		//      DbgPrint("PatchDword(0x%08x, 0x%08x);\n", &saveStub[i], saveStub[i]);
		//}
		// patch the actual function to jump to our replaced one
		PatchInJump(addr, dest, FALSE);
	}
}

HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System)
{
	// Setup our path
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, System ? "\\System??\\%s" : "\\??\\%s", szDrive);

	// Setup our strings
	ANSI_STRING linkname, devicename;
	RtlInitAnsiString(&linkname, szDestinationDrive);
	RtlInitAnsiString(&devicename, szDeviceName);

	//check if already mapped
	if(FileExists(szDrive))
		return S_OK;

	// Create finally
	NTSTATUS status = ObCreateSymbolicLink(&linkname, &devicename);
	return (status >= 0) ? S_OK : S_FALSE;
}

HRESULT DeleteSymbolicLink(CHAR* szDrive, BOOL System)
{
	// Setup our path
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, System ? "\\System??\\%s" : "\\??\\%s", szDrive);

	// Setup our string
	ANSI_STRING linkname;
	RtlInitAnsiString(&linkname, szDestinationDrive);
	
	// Delete finally
	NTSTATUS status = ObDeleteSymbolicLink(&linkname);
	return (status >= 0) ? S_OK : S_FALSE;
}

BOOL CReadFile(const CHAR * FileName, MemoryBuffer &pBuffer)
{
	HANDLE hFile; DWORD dwFileSize, dwNumberOfBytesRead;
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		//DbgPrint("CReadFile - CreateFile failed");
		return FALSE;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	PBYTE lpBuffer = (BYTE*)malloc(dwFileSize);
	if(lpBuffer == NULL)
	{
		CloseHandle(hFile);
		//DbgPrint("CReadFile - malloc failed");
		return FALSE;
	}
	if(ReadFile(hFile, lpBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) == FALSE)
	{
		free(lpBuffer);
		CloseHandle(hFile);
		//DbgPrint("CReadFile - ReadFile failed");
		return FALSE;
	}
	else if (dwNumberOfBytesRead != dwFileSize)
	{
		free(lpBuffer);
		CloseHandle(hFile);
		//DbgPrint("CReadFile - Failed to read all the bytes");
		return FALSE;
	}
	CloseHandle(hFile);
	pBuffer.Add(lpBuffer, dwFileSize);
	free(lpBuffer);
	return TRUE;
}

BOOL CWriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size)
{	
	// Open our file
	HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(fHandle == INVALID_HANDLE_VALUE)
	{
		//DbgPrint("CWriteFile - CreateFile failed");
		return FALSE;
	}

	// Write our data and close
	DWORD writeSize = Size;
	if(WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE)
	{
		//DbgPrint("CWriteFile - WriteFile failed");
		return FALSE;
	}

	CloseHandle(fHandle);
	return TRUE;
}

BOOL FileExists(LPCSTR lpFileName)
{
	// Try and get the file attributes.
	if(GetFileAttributes(lpFileName) == -1)
	{
		DWORD lastError = GetLastError();
		if(lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
			return FALSE;
	}

	// The file must exist if we got this far..
	return TRUE;
}

HRESULT SetMemory(VOID* Destination, VOID* Source, DWORD Length)
{
	if(isDevkit)
		return DmSetMemory(Destination, Length, Source, NULL);

	memcpy(Destination, Source, Length);
	return S_OK;
}

DWORD ApplyPatches(CHAR* FilePath, const VOID* DefaultPatches)
{
	// Read our file
	DWORD patchCount = 0;
	MemoryBuffer mbPatches;
	DWORD* patchData = (DWORD*)DefaultPatches;

	// Check if we have our override patches
	if (FilePath != NULL && FileExists(FilePath))
	{
		if (!CReadFile(FilePath, mbPatches))
		{
			//DbgPrint("ApplyPatches - CReadFile failed");
			return 0;
		}

		// Set our patch data now..
		patchData = (DWORD*)mbPatches.GetData();
	}

	if (patchData == NULL)
		return 0;

	while (*patchData != 0xFFFFFFFF)
	{
		BOOL inHvMode = (patchData[0] < 0x40000);
		QWORD patchAddr = inHvMode ? (0x200000000 * (patchData[0] / 0x10000)) + patchData[0] : (QWORD)patchData[0];
		SetMemory((VOID*)patchData[0], &patchData[2], patchData[1] * sizeof(DWORD));
		patchData += (patchData[1] + 2);
		patchCount++;
	}

	return patchCount;
}

typedef struct _LAUNCH_SYS_MSG {
	XNOTIFYQUEUEUI_TYPE Type;
	PWCHAR Message;
	DWORD Delay;
} LAUNCH_SYS_MSG, *PLAUNCH_SYS_MSG;
LAUNCH_SYS_MSG notifyData;

VOID xNotifyThread()
{
	Sleep(notifyData.Delay);
	XNotifyQueueUI(notifyData.Type, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, notifyData.Message, NULL);
}

VOID XNotifyUI(PWCHAR displayText, DWORD dwDelay, XNOTIFYQUEUEUI_TYPE notifyType)
{
	notifyData.Type = notifyType;
	notifyData.Message = displayText;
	notifyData.Delay = dwDelay;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)xNotifyThread, NULL, 0, NULL);
}

VOID launchSysThread(LPTHREAD_START_ROUTINE func)
{
	HANDLE hThread;
	DWORD dwThreadId;
	ExCreateThread(&hThread, 0, &dwThreadId, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)func, NULL, EX_CREATE_FLAG_SYSTEM | EX_CREATE_FLAG_SUSPENDED);
	XSetThreadProcessor(hThread, 4);
	ResumeThread(hThread);
	CloseHandle(hThread);
}