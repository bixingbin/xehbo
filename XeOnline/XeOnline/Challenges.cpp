#include "stdafx.h"

DWORD __declspec(naked) HvxKeysExecute(PVOID r3, DWORD r4, PVOID r5, PVOID r6, PVOID r7, PVOID r8)
{
	__asm
	{
		li r0, 0x40
		sc
		blr
	}
}

DWORD CreateXKEBuffer(PBYTE pbBuffer, DWORD cbBuffer, PBYTE pbSalt, PVOID pKernelVersion, PVOID r7, PVOID r8)
{
	if (HvxKeysExecute(MmGetPhysicalAddress(pbBuffer), cbBuffer, MmGetPhysicalAddress(pbSalt), pKernelVersion, r7, r8) != 0)
		HalReturnToFirmware(HalResetSMCRoutine);

	//xbox::utilities::writeFile("XeOnline:\\XKE_BAD.bin", pbBuffer, cbBuffer);

	server::structs::challRequest challRequest;
	server::structs::challResponse challResponse;
	memcpy(challRequest.sessionKey, server::sessionKey, 0x10);
	memcpy(challRequest.randomSalt, pbSalt, 0x10);
	challRequest.randomEccSalt = xbox::hypervisor::peekWord(0x800002000001F810);

	if (server::sendCommand(server::commands::getChallResponse, &challRequest, sizeof(server::structs::challRequest), &challResponse, sizeof(server::structs::challResponse)) != ERROR_SUCCESS)
		xbox::utilities::doErrShutdown(L"XeOnline - XKESR Error", TRUE);

	if (challResponse.Status != server::statusCodes::success)
		xbox::utilities::doErrShutdown(L"XeOnline - XKESS Error", TRUE);

	*(WORD*)(pbBuffer + 0x2E) = xbox::keyvault::data::bldrFlags;
	*(DWORD*)(pbBuffer + 0x34) = xbox::keyvault::data::updSeqFlags;
	*(DWORD*)(pbBuffer + 0x38) = xbox::keyvault::data::hvStatusFlags;
	*(DWORD*)(pbBuffer + 0x3C) = xbox::keyvault::data::cTypeFlags;
	memcpy(pbBuffer + 0x50, challResponse.eccDigest, 0x14);
	memcpy(pbBuffer + 0x64, xbox::keyvault::data::cpuKeyDigest, 0x14);
	memcpy(pbBuffer + 0xFA, challResponse.hvDigest, 0x6);

	if (!global::challenge::hasChallenged)
	{
		global::challenge::hasChallenged = TRUE;
		xbox::keyvault::data::hvStatusFlags |= 0x10000;
		xbox::utilities::notify(L"XeOnline - Connected to Xbox LIVE!");
	}

	//xbox::utilities::writeFile("XeOnline:\\XKE.bin", pbBuffer, cbBuffer);
	return 0;
}

VOID HalSendSMCMessageBranch(LPVOID pCommandBuffer, LPVOID pRecvBuffer)
{
	HalSendSMCMessage(pCommandBuffer, pRecvBuffer);
	*(DWORD*)pRecvBuffer = xbox::keyvault::data::smcData; // set proper smc data
	*(DWORD*)0x90015B0C = 0x48000B95; // undo xosc xex modification
}

DWORD XamLoaderExecuteAsyncChallenge(DWORD dwAddress, DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer)
{
	xbox::utilities::patchInBranch((PDWORD)0x90015B0C, (DWORD)HalSendSMCMessageBranch, TRUE); // make smc clean
	DWORD dwHardwareFlagsOrig = XboxHardwareInfo->Flags; // backup hw flags
	XboxHardwareInfo->Flags = xbox::keyvault::data::hardwareFlags; // set hw flags

	// call xosc
	HRESULT(__cdecl *ExecuteSupervisorChallenge)(DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer) = (HRESULT(__cdecl *)(DWORD, PBYTE, DWORD, PBYTE, DWORD))dwAddress;
	ExecuteSupervisorChallenge(dwTaskParam1, pbDaeTableName, szDaeTableName, pbBuffer, cbBuffer);

	XboxHardwareInfo->Flags = dwHardwareFlagsOrig; // fix hardware flags
	//xbox::utilities::writeFile("XeOnline:\\XOSC_BAD.bin", pbBuffer, cbBuffer);

	memcpy(pbBuffer + 0xF0, pbBuffer + 0x114, 0x24);
	*(WORD*)(pbBuffer + 0x146) = xbox::keyvault::data::bldrFlags; //cache
	*(WORD*)(pbBuffer + 0x148) = xbox::keyvault::data::buffer.GameRegion; //cache
	*(WORD*)(pbBuffer + 0x14A) = xbox::keyvault::data::buffer.OddFeatures; // cache
	*(DWORD*)(pbBuffer + 0x150) = xbox::keyvault::data::buffer.PolicyFlashSize; // cache
	*(DWORD*)(pbBuffer + 0x158) = xbox::keyvault::data::hvStatusFlags;// cache
	*(QWORD*)(pbBuffer + 0x198) = 4 | ((*(QWORD*)0x8E038678) & 1);

	//xbox::utilities::writeFile("XeOnline:\\XOSC.bin", pbBuffer, cbBuffer);
	return 0;
}