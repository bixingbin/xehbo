#include "stdafx.h"

namespace xbox {
	namespace utilities {
		VOID log(const CHAR* strFormat, ...)
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

		HRESULT setLiveBlock(BOOL enable)
		{
			DWORD value = enable ? 1 : 0;

			if (global::isDevkit)
			{
				if (enable) *(DWORD*)0x8161DDD4 = 0x4E554C4C;
				else *(DWORD*)0x8161DDD4 = 0x50524F44;
				return S_OK;
			}

			if (!dlaunchSetOptValByName) dlaunchSetOptValByName = (BOOL(__cdecl *)(CONST PCHAR, PDWORD))xbox::utilities::resolveFunction("launch.xex", 10);

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
			wcsncpy(global::wNotifyMsg, msg, sizeof(global::wNotifyMsg) / sizeof(WCHAR));
		}

		BOOL isNotifyMsgSet()
		{
			return (global::wNotifyMsg[0] != 0 && global::wNotifyMsg[1] != 0);
		}

		VOID launchDefaultApp()
		{
			XSetLaunchData(NULL, 0);
			XamLoaderLaunchTitleEx(XLAUNCH_KEYWORD_DEFAULT_APP, NULL, NULL, 0);
		}

		VOID rebootToDash()
		{
			xbox::utilities::createThread(launchDefaultApp);
		}

		VOID doErrShutdown(WCHAR* msg, BOOL reboot)
		{
			xbox::utilities::notify(msg);
			Sleep(7000);
			HalReturnToFirmware(reboot ? HalFatalErrorRebootRoutine : HalResetSMCRoutine);
		}

		VOID patchInJump(DWORD* Address, DWORD Destination, BOOL Linked)
		{
			Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
			if (Destination & 0x8000) Address[0] += 1;
			Address[1] = 0x396B0000 + (Destination & 0xFFFF);
			Address[2] = 0x7D6903A6;
			Address[3] = Linked ? 0x4E800421 : 0x4E800420;
		}

		VOID patchInBranch(DWORD* Address, DWORD Destination, BOOL Linked)
		{
			Address[0] = (0x48000000 + ((Destination - (DWORD)Address) & 0x3FFFFFF) | Linked);
		}

		FARPROC resolveFunction(CHAR* ModuleName, DWORD Ordinal)
		{
			HMODULE mHandle = GetModuleHandle(ModuleName);
			return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
		}

		IMAGE_SECTION_HEADER* findNtSection(IMAGE_SECTION_HEADER* Sections, WORD SectionCount, CHAR* SectionName) {

			// Go through and search for our section
			for (WORD x = 0; x < SectionCount; x++) {
				if (strcmp((CHAR*)Sections[x].Name, SectionName) == 0)
					return &Sections[x];
			}

			return NULL;
		}

		DWORD getModuleImportCallAddress(LDR_DATA_TABLE_ENTRY* moduleHandle, CHAR* ImportedModuleName, DWORD Ordinal)
		{
			DWORD address = (DWORD)xbox::utilities::resolveFunction(ImportedModuleName, Ordinal);
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

		DWORD patchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress)
		{
			LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(Module);
			return (moduleHandle == NULL) ? S_FALSE : patchModuleImport(moduleHandle, ImportedModuleName, Ordinal, PatchAddress);
		}

		DWORD patchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress)
		{
			// First resolve this imports address
			DWORD address = (DWORD)xbox::utilities::resolveFunction(ImportedModuleName, Ordinal);
			if (address == NULL)
				return S_FALSE;

			// Get our header field from this module
			VOID* headerBase = Module->XexHeaderBase;
			PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
			if (importDesc == NULL)
				return S_FALSE;

			// Our result
			DWORD result = 2; // No occurances patched

			// Get our string table position
			CHAR* stringTable = (CHAR*)(importDesc + 1);

			// Get our first entry
			XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

			// Loop through our table
			for (DWORD x = 0; x < importDesc->ModuleCount; x++) {

				// Go through and search all addresses for something that links
				DWORD* importAdd = (DWORD*)(importTable + 1);
				for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {

					// Check the address of this import
					DWORD value = *((DWORD*)importAdd[y]);
					if (value == address) {

						// We found a matching address address
						xbox::utilities::setMemory((DWORD*)importAdd[y], &PatchAddress, 4);
						DWORD newCode[4];
						xbox::utilities::patchInJump(newCode, PatchAddress, FALSE);
						xbox::utilities::setMemory((DWORD*)importAdd[y + 1], newCode, 16);

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

		BOOL readFile(const CHAR * FileName, MemoryBuffer &pBuffer)
		{
			HANDLE hFile; DWORD dwFileSize, dwNumberOfBytesRead;
			hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				//DbgPrint("readFile - CreateFile failed");
				return FALSE;
			}
			dwFileSize = GetFileSize(hFile, NULL);
			PBYTE lpBuffer = (BYTE*)malloc(dwFileSize);
			if (lpBuffer == NULL)
			{
				CloseHandle(hFile);
				//DbgPrint("readFile - malloc failed");
				return FALSE;
			}
			if (ReadFile(hFile, lpBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) == FALSE)
			{
				free(lpBuffer);
				CloseHandle(hFile);
				//DbgPrint("readFile - ReadFile failed");
				return FALSE;
			}
			else if (dwNumberOfBytesRead != dwFileSize)
			{
				free(lpBuffer);
				CloseHandle(hFile);
				//DbgPrint("readFile - Failed to read all the bytes");
				return FALSE;
			}
			CloseHandle(hFile);
			pBuffer.Add(lpBuffer, dwFileSize);
			free(lpBuffer);
			return TRUE;
		}

		BOOL writeFile(const CHAR* FilePath, const VOID* Data, DWORD Size)
		{
			// Open our file
			HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fHandle == INVALID_HANDLE_VALUE)
			{
				//DbgPrint("writeFile - CreateFile failed");
				return FALSE;
			}

			// Write our data and close
			DWORD writeSize = Size;
			if (WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE)
			{
				//DbgPrint("writeFile - WriteFile failed");
				return FALSE;
			}

			CloseHandle(fHandle);
			return TRUE;
		}

		BOOL fileExists(LPCSTR lpFileName)
		{
			// Try and get the file attributes.
			if (GetFileAttributes(lpFileName) == -1)
			{
				DWORD lastError = GetLastError();
				if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
					return FALSE;
			}

			// The file must exist if we got this far..
			return TRUE;
		}

		HRESULT setMemory(VOID* Destination, DWORD Value)
		{
			return setMemory(Destination, &Value, 4);
		}

		HRESULT setMemory(VOID* Destination, VOID* Source, DWORD Length)
		{
			if (global::isDevkit)
			{
				if (!DevSetMemory) DevSetMemory = (HRESULT(__cdecl *)(LPVOID, DWORD, LPCVOID, LPDWORD))xbox::utilities::resolveFunction("xbdm.xex", 40);
				if (DevSetMemory(Destination, Length, Source, NULL) == MAKE_HRESULT(0, 0x2DA, 0))
					return ERROR_SUCCESS;
			}
			else
			{
				memcpy(Destination, Source, Length);
				return ERROR_SUCCESS;
			}

			// We have a problem...
			return E_FAIL;
		}

		DWORD applyPatches(VOID* patches, CHAR* filePath)
		{
			// Read our file
			DWORD patchCount = 0;
			MemoryBuffer mbPatches;
			DWORD* patchData = (DWORD*)patches;

			// Check if we have our override patches
			if (filePath != NULL && fileExists(filePath))
			{
				if (!readFile(filePath, mbPatches))
				{
					//DbgPrint("ApplyPatches - readFile failed");
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
				xbox::utilities::setMemory((VOID*)patchData[0], &patchData[2], patchData[1] * sizeof(DWORD));
				patchData += (patchData[1] + 2);
				patchCount++;
			}

			return patchCount;
		}

		HRESULT applyDefaultPatches()
		{
			PVOID patchesAddr;
			DWORD patchesSize;

			if (!XGetModuleSection(global::modules::client, global::isDevkit ? "dev" : "rgh", &patchesAddr, &patchesSize))
				return E_FAIL;

			return applyPatches(patchesAddr) != 0 ? S_OK : E_FAIL;
		}

		HRESULT mountSystem()
		{
			wstring path(global::modules::client->FullDllName.Buffer);
			path = path.substr(0, path.find_last_of(L"\\") + 1);

			STRING deviceName;
			STRING linkName;
			RtlInitAnsiString(&deviceName, string(path.begin(), path.end()).c_str());
			RtlInitAnsiString(&linkName, "\\System??\\" CONFIG_NAME_LINKER);
			ObDeleteSymbolicLink(&linkName);
			return ObCreateSymbolicLink(&linkName, &deviceName);
		}

		VOID xNotifyThread()
		{
			Sleep(notifyData.Delay);
			XNotifyQueueUI(notifyData.Type, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, notifyData.Message, NULL);
		}

		VOID notify(PWCHAR displayText, DWORD dwDelay, XNOTIFYQUEUEUI_TYPE notifyType)
		{
			notifyData.Type = notifyType;
			notifyData.Message = displayText;
			notifyData.Delay = dwDelay;

			createThread(xNotifyThread, FALSE);
		}

		VOID createThread(PVOID lpStartAddress, BOOL systemThread, DWORD dwHardwareThread)
		{
			if (systemThread)
			{
				HANDLE hThread;
				DWORD dwThreadId;
				ExCreateThread(&hThread, 0, &dwThreadId, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)lpStartAddress, NULL, EX_CREATE_FLAG_SYSTEM | EX_CREATE_FLAG_SUSPENDED);
				XSetThreadProcessor(hThread, dwHardwareThread);
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
			else CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, NULL, 0, NULL);
		}
	}
}