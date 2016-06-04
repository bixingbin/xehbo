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

	xbox::utilities::writeFile("XeOnline:\\XKE_BAD.bin", pbBuffer, cbBuffer);

	server::structs::challRequest challRequest;
	server::structs::challResponse challResponse;
	memcpy(challRequest.sessionKey, server::sessionKey, 0x10);
	memcpy(challRequest.randomSalt, pbSalt, 0x10);
	challRequest.randomEccSalt = xbox::hypervisor::peekWord(0x800002000001F810);

	if (server::sendCommand(server::commands::getChallResponse, &challRequest, sizeof(server::structs::challRequest), &challResponse, sizeof(server::structs::challResponse)) != ERROR_SUCCESS)
		xbox::utilities::doErrShutdown(L"XeOnline - XKESR Error", TRUE);

	if (challResponse.Status != server::statusCodes::success)
		xbox::utilities::doErrShutdown(L"XeOnline - XKESS Error", TRUE);

	memcpy(pbBuffer + 0x50, challResponse.eccDigest, 0x14);
	memcpy(pbBuffer + 0xFA, challResponse.hvDigest, 0x6);

	if (!global::challenge::hasChallenged)
	{
		global::challenge::hasChallenged = TRUE;
		xbox::keyvault::data::hvStatusFlags |= 0x10000;
		xbox::hypervisor::pokeDword(0x30, xbox::keyvault::data::hvStatusFlags);
		xbox::utilities::notify(L"XeOnline - Fully Stealthed!");
		xbox::utilities::writeFile("XeOnline:\\XKE.bin", pbBuffer, cbBuffer);
		return 0;
	}

	xbox::utilities::writeFile("XeOnline:\\XKE_CRL.bin", pbBuffer, cbBuffer);
	return 0;
}

DWORD XamLoaderExecuteAsyncChallenge(DWORD dwAddress, DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer)
{
	BYTE xenonAndZephyrHash[] = { 0x7E, 0xF9, 0x9A, 0x87, 0xE3, 0xCD, 0x7A, 0x9E, 0x2B, 0xE5, 0x39, 0x5E, 0x66, 0xC2, 0xC0, 0xFB };
	BYTE falconAndJasperHash[] = { 0x82, 0xC1, 0xF0, 0x00, 0x9E, 0x79, 0x97, 0xF3, 0x34, 0x0E, 0x01, 0x45, 0x1A, 0xD0, 0x32, 0x57 };
	BYTE trinityAndCoronaHash[] = { 0xD1, 0x32, 0xFB, 0x43, 0x9B, 0x48, 0x47, 0xE3, 0x9F, 0xE5, 0x46, 0x46, 0xF0, 0xA9, 0x9E, 0xB1 };

	memcpy((PVOID)0x8E03AA30, xbox::keyvault::data::cpuKeyDigest, 0x10);
	memcpy((PVOID)0x8E03AA40, xbox::keyvault::data::keyvaultDigest, 0x10);
	switch (xbox::keyvault::data::consoleType)
	{
	case 1: memcpy((PVOID)0x8E03AA50, xenonAndZephyrHash, 0x10); break;
	case 2: memcpy((PVOID)0x8E03AA50, falconAndJasperHash, 0x10); break;
	case 3: memcpy((PVOID)0x8E03AA50, falconAndJasperHash, 0x10); break;
	case 4: memcpy((PVOID)0x8E03AA50, trinityAndCoronaHash, 0x10); break;
	case 5: memcpy((PVOID)0x8E03AA50, trinityAndCoronaHash, 0x10); break;
	default: xbox::utilities::doErrShutdown(L"Currently not supported, sorry!"); break;
	}

	HRESULT(__cdecl *ExecuteSupervisorChallenge)(DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer) = (HRESULT(__cdecl *)(DWORD, PBYTE, DWORD, PBYTE, DWORD))dwAddress;
	ExecuteSupervisorChallenge(dwTaskParam1, pbDaeTableName, szDaeTableName, pbBuffer, cbBuffer);

	xbox::utilities::writeFile("XeOnline:\\XOSC_BAD.bin", pbBuffer, cbBuffer);

	memcpy(pbBuffer + 0xF0, pbBuffer + 0x114, 0x24);
	*(BYTE*)(pbBuffer + 0x83) = xbox::keyvault::data::buffer.XeikaCertificate.Data.OddData.PhaseLevel;
	*(WORD*)(pbBuffer + 0x146) = xbox::keyvault::data::bldrFlags;
	*(WORD*)(pbBuffer + 0x148) = xbox::keyvault::data::buffer.GameRegion;
	*(WORD*)(pbBuffer + 0x14A) = xbox::keyvault::data::buffer.OddFeatures;
	*(DWORD*)(pbBuffer + 0x150) = xbox::keyvault::data::buffer.PolicyFlashSize;
	*(DWORD*)(pbBuffer + 0x158) = xbox::keyvault::data::hvStatusFlags;
	*(DWORD*)(pbBuffer + 0x1D0) = xbox::keyvault::data::hardwareFlags;

	xbox::utilities::writeFile("XeOnline:\\XOSC.bin", pbBuffer, cbBuffer);
	return 0;
}