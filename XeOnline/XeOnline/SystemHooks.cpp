#include "stdafx.h"

extern BOOL isDevkit;
extern DWORD supportedVersion;
XEX_EXECUTION_ID spoofedExecutionId;
Detour<HRESULT> *XuiPNGTextureLoaderDetour;

HRESULT XeKeysExecuteHook(PBYTE pbBuffer, DWORD cbBuffer, PBYTE pbSalt, PXBOX_KRNL_VERSION pKernelVersion, PDWORD r7, PDWORD r8)
{
	return CreateXKEBuffer(pbBuffer, cbBuffer, pbSalt);
}

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

BOOL XexCheckExecutablePrivilegeHook(DWORD priv)
{
	// Allow insecure sockets for all titles
	if (priv == XEX_PRIVILEGE_INSECURE_SOCKETS)
		return TRUE;

	return XexCheckExecutablePrivilege(priv);
}

BOOL InitializeHooks()
{
	DWORD spoofedVersion = XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe;
	spoofedExecutionId.Version = spoofedVersion;
	spoofedExecutionId.BaseVersion = spoofedVersion;
	spoofedExecutionId.TitleID = 0xFFFE07D1;

	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 299, (DWORD)RtlImageXexHeaderFieldHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 404, (DWORD)XexCheckExecutablePrivilegeHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook) != S_OK) return FALSE;
	if (PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 607, (DWORD)XeKeysExecuteHook) != S_OK) return FALSE;
	PatchInJump((PDWORD)(isDevkit ? 0x8175CDF0 : 0x8169C5D8), (DWORD)XamLoaderExecuteAsyncChallenge, FALSE);
	PatchInJump((PDWORD)(isDevkit ? 0x81795664 : 0x816CE284), (DWORD)setupCustomSkin, TRUE);

	XuiPNGTextureLoaderDetour = new Detour<HRESULT>;
	XuiPNGTextureLoaderDetour->SetupDetour(isDevkit ? 0x819022B0 : 0x817841B0, XuiPNGTextureLoaderHook);

	// All done
	return TRUE;
}