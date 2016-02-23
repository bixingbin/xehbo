#include "stdafx.h"

VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle)
{
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook);
	PatchModuleImport(ModuleHandle, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook);

	XEX_EXECUTION_ID* pExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(ModuleHandle->XexHeaderBase, 0x00040006);

	if (pExecutionId == 0)
		return;

	if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"hud.xex") == 0)
		patchHud(ModuleHandle);

	//int exVersion = (pExecutionId->Version >> 8) & 0xFF;
}