#include "stdafx.h"

extern BOOL isDevkit;
extern DWORD supportedVersion;
extern PLDR_DATA_TABLE_ENTRY hXam;
XEX_EXECUTION_ID spoofedExecutionId;
Detour<HRESULT> *XuiPNGTextureLoaderDetour;

HRESULT XeKeysExecuteHook(PBYTE pbBuffer, DWORD cbBuffer, PBYTE pbSalt, PXBOX_KRNL_VERSION pKernelVersion, PDWORD r7, PDWORD r8)
{
	return CreateXKEBuffer(pbBuffer, cbBuffer, pbSalt);
}

//PVOID RtlImageXexHeaderFieldHook(PVOID headerBase, DWORD imageKey)
//{
//	PVOID ret = RtlImageXexHeaderField(headerBase, imageKey);
//
//	if (imageKey == 0x40006)
//	{
//		if (ret)
//		{
//			switch (((XEX_EXECUTION_ID*)ret)->TitleID)
//			{
//			case 0xFFFE07FF: // XShell
//			case 0xFFFF0055: // Xex Menu
//			case 0xC0DE9999: // Xex Menu
//			{
//				SetMemory(ret, &spoofedExecutionId, sizeof(XEX_EXECUTION_ID));
//				break;
//			}
//			}
//		}
//		else SetMemory(ret, &spoofedExecutionId, sizeof(XEX_EXECUTION_ID));
//	}
//
//	return ret;
//}

VOID* RtlImageXexHeaderFieldHook(VOID* headerBase, DWORD imageKey)
{
	// Call it like normal
	VOID* retVal = RtlImageXexHeaderField(headerBase, imageKey);

	// See if we are looking for our Execution ID and if its found lets patch it if we must
	if (imageKey == 0x40006 && retVal)
	{
		switch (((XEX_EXECUTION_ID*)retVal)->TitleID)
		{
		case 0xFFFF0055: //Xex Menu
		case 0xFFFE07FF: //XShelXDK
		case 0xFFFF011D: //dl installer
		{
			SetMemory(retVal, &spoofedExecutionId, sizeof(XEX_EXECUTION_ID));
			break;
		}
		}
	}
	else if (imageKey == 0x40006 && !retVal)
	{
		// We couldn't find an execution id so lets return ours
		retVal = &spoofedExecutionId;
	}

	// Return like normal
	return retVal;
}

//PVOID RtlImageXexHeaderFieldHook(PVOID XexHeaderBase, DWORD ImageField)
//{
//	PVOID ret = RtlImageXexHeaderField(XexHeaderBase, ImageField);
//
//	//if (ImageField == XEX_HEADER_EXECUTION_ID)
//	//{
//	//	XEX_EXECUTION_ID* execId = (XEX_EXECUTION_ID*)ret;
//
//	//	switch (execId->TitleID)
//	//	{
//	//	case 0xFFFE07FF: // XShell
//	//	case 0xFFFF0055: // Xex Menu
//	//	case 0xC0DE9999: // Xex Menu
//	//	{
//	//		DWORD spoofedVersion = XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe;
//	//		execId->Version = spoofedVersion;
//	//		execId->BaseVersion = spoofedVersion;
//	//		execId->TitleID = 0xFFFE07D1;
//
//	//		SetMemory(ret, &spoofedExecutionId, sizeof(XEX_EXECUTION_ID));
//	//		break;
//	//	}
//	//	}
//	//}
//
//	return ret;
//}

NTSTATUS XexLoadExecutableHook(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion) 
{
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadExecutable(szXexName, &mHandle, dwModuleTypeFlags, dwMinimumVersion);
	if (pHandle != NULL) *pHandle = mHandle;
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);		
	return result;
}

NTSTATUS XexLoadImageHook(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle)
{
	HANDLE mHandle = NULL;
	NTSTATUS result = XexLoadImage(szXexName, dwModuleTypeFlags, dwMinimumVersion, &mHandle);
	if (pHandle != NULL) *pHandle = mHandle;
	if (NT_SUCCESS(result)) InitializeTitleSpecificHooks((PLDR_DATA_TABLE_ENTRY)mHandle);	
	return result;
}

#pragma region Anti-Piracy Stuff

DWORD XSecurityCreateProcessHook(DWORD dwHardwareThread)
{
	return ERROR_SUCCESS;
}

VOID XSecurityCloseProcessHook()
{
	return;
}

DWORD XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (lpCompletionRoutine)
		lpCompletionRoutine(0, 0, lpOverlapped);

	return ERROR_SUCCESS;
}

//DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation)
//{
//	if (pFailureInformation->dwSize == 0x14)
//	{
//		pFailureInformation->dwBlocksChecked = 0x64;
//		pFailureInformation->dwFailedHashes = 0;
//		pFailureInformation->dwFailedReads = 0;
//		pFailureInformation->dwTotalBlocks = 0x64;
//	}
//	else if (pFailureInformation->dwSize == sizeof(XSECURITY_FAILURE_INFORMATION))
//	{
//		pFailureInformation->dwBlocksChecked = 0x100;
//		pFailureInformation->dwFailedHashes = 0;
//		pFailureInformation->dwFailedReads = 0;
//		pFailureInformation->dwTotalBlocks = 0x100;
//		pFailureInformation->fComplete = TRUE;
//	}
//	else return ERROR_NOT_ENOUGH_MEMORY;
//
//	return ERROR_SUCCESS;
//}

DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation)
{
	if (pFailureInformation->dwSize != 0x18) return ERROR_NOT_ENOUGH_MEMORY;
	pFailureInformation->dwBlocksChecked = 0;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = 0;
	pFailureInformation->fComplete = TRUE;
	return ERROR_SUCCESS;
}

NTSTATUS XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress)
{
	if (hand == hXam)
	{
		switch (dwOrdinal) {
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

	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

#pragma endregion

BOOL InitializeHooks()
{
	DWORD spoofedVersion = XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe;
	spoofedExecutionId.Version = spoofedVersion;
	spoofedExecutionId.BaseVersion = spoofedVersion;
	spoofedExecutionId.TitleID = 0xFFFE07D1;

	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 299, (DWORD)RtlImageXexHeaderFieldHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 607, (DWORD)XeKeysExecuteHook) != S_OK) return FALSE;
	PatchInJump((PDWORD)(isDevkit ? 0x8175CDF0 : 0x8169C5D8), (DWORD)XamLoaderExecuteAsyncChallenge, FALSE);

#pragma region XuiPNGTextureLoaderHook
	DWORD emptySpace = isDevkit ? 0x81DE30D0 : 0x81B07000;
	PatchInJump((PDWORD)emptySpace, (DWORD)XuiPNGTextureLoaderHook, FALSE);
	PatchInBranch((PDWORD)(isDevkit ? 0x8178DBA4 : 0x816C7ADC), emptySpace, TRUE);
#pragma endregion

	PatchInJump((PDWORD)(isDevkit ? 0x81795664 : 0x816CE284), (DWORD)setupCustomSkin, TRUE);

	// All done
	return TRUE;
}