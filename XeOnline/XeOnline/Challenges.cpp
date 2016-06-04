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

DWORD setXoscProccessDigest()
{
	//TODO:
	//Add checks for different XOSC versions
	//Send different version XOSC to server for us to look at
	HANDLE modHand;
	WORD tval = 0;
	PLDR_DATA_TABLE_ENTRY ldat;
	BYTE hashbuf[0x14];
	BYTE nullData[0x10];
	BYTE smcCmd[0x10];
	BYTE smcResp[0x10];
	memset(smcCmd, 0, 0x10);
	memset(smcResp, 0, 0x10);
	memset(nullData, 0, 16);
	memcpy(hashbuf, xbox::keyvault::data::keyvaultDigest, 0x14);//this is what i found in xex
	//memcpy(hashbuf + 0x10, resp->zeroEncryptedConsoleType, 4); was not found in my xosc xex

	if (NT_SUCCESS(XexGetModuleHandle("xam.xex", &modHand)))
	{
		PIMAGE_XEX_HEADER xhead;
		ldat = (PLDR_DATA_TABLE_ENTRY)modHand;
		xhead = (PIMAGE_XEX_HEADER)ldat->XexHeaderBase;
		if (xhead != NULL)
		{
			XECRYPT_SHA_STATE xsha;
			XeCryptShaInit(&xsha);
			memcpy(&xsha, &xamSha, sizeof(XECRYPT_SHA_STATE));
			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, nullData, 0x10);
			XeCryptShaFinal(&xsha, hashbuf, 0x14);
			tval = 1;
		}
	}
	if (NT_SUCCESS(XexGetModuleHandle("xboxkrnl.exe", &modHand)))
	{
		PIMAGE_XEX_HEADER xhead;
		ldat = (PLDR_DATA_TABLE_ENTRY)modHand;
		xhead = (PIMAGE_XEX_HEADER)ldat->XexHeaderBase;
		if (xhead != NULL)
		{
			WORD tword = 0;
			BYTE macaddr[6];
			if (NT_SUCCESS(ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, macaddr, 6, &tword)))
			{
				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				memcpy(&xsha, &kernSha, sizeof(XECRYPT_SHA_STATE));
				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, macaddr, 6);
				XeCryptShaFinal(&xsha, hashbuf, 0x14);
				tval |= 2;
			}
			else
				return  ERROR_INVALID_PARAMETER;// STATUS_INVALID_PARAMETER_7;
		}
	}

	if (NT_SUCCESS(XexGetModuleHandle(NULL, &modHand))) // gets the current title handle
	{
		PIMAGE_XEX_HEADER xhead;
		ldat = (PLDR_DATA_TABLE_ENTRY)modHand;
		xhead = (PIMAGE_XEX_HEADER)ldat->XexHeaderBase;
		if (xhead != NULL)
		{
			BYTE mval;
			smcCmd[0] = smc_query_version;
			HalSendSMCMessage(smcCmd, smcResp);
			mval = ((xbox::keyvault::data::hardwareFlags) >> 28) & 0xF;

			memcpy(smcResp, smcVers[mval].smcVer, 4); // this will clean things up for jtags (mostly, see xenon/zephyr comment) and leave the async info byte intact
			for (int i = 0; i < 4; i++) { smcResp[i] ^= 0xFF; } //unobfuscate

			XEX_EXECUTION_ID* pExecutionId;
			XamGetExecutionId(&pExecutionId);
			XECRYPT_SHA_STATE xsha;
			XeCryptShaInit(&xsha);

			if (pExecutionId->TitleID == 0xFFFE07D1)//sha state for dash on HDD is same as on Flash
				memcpy(&xsha, dashSha, sizeof(XECRYPT_SHA_STATE));//so no need to find out where its launched from
			else//not spoofing or on dash
				memcpy(&xsha, &global::challenge::xShaCurrentXex, sizeof(XECRYPT_SHA_STATE));

			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, smcResp, 0x5);
			XeCryptShaFinal(&xsha, hashbuf, 0x14);

			tval |= 4;
		}
	}

	//hash xosc xex. 
	//we do not have any patches on xosc.xex so it should be clean unless it sets dirty values within itself.
	//but we are spoofing the clean data it reads so its probably clean
	DWORD one = *(DWORD*)0x90015B6C, two = *(DWORD*)0x90015B4C,
		three = *(DWORD*)0x90015B68, four = *(DWORD*)0x90015B48;

	XeCryptSha((PBYTE)(((DWORD)(((one) & 0xFFFF) | ((((two) & 0xFFFF) << 16)))) & 0xFFFFFFFF), (((DWORD)(((three) & 0xFFFF) | ((((four) & 0xFFFF) << 16)))) & 0xFFFFFFFF), hashbuf, 0x14, 0, 0, hashbuf, 0x14);
	
	//HASH ONLY XOSC SO WE CAN CHECK VERSIONS
	//XeCryptSha((PBYTE)(((DWORD)(((one) & 0xFFFF) | ((((two) & 0xFFFF) << 16)))) & 0xFFFFFFFF), (((DWORD)(((three) & 0xFFFF) | ((((four) & 0xFFFF) << 16)))) & 0xFFFFFFFF),0, 0, 0, 0, hashbuf, 0x14);

	hashbuf[0] = (0 | tval) & 0xFF;//does it really use timestamp?// i dont think so
	//hashbuf[0] = one of these {0,1,2,3,4,5,6,7}; if its 7 that means every process was hashed
	//look at any recent xosc resp to prove mmy theory 
	// (2/2)responses i looked at had 7 as the value
	memcpy(xbox::keyvault::data::proccessDigest, hashbuf, 0x14);//xosc resp only keeps 0x10 bytes though
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
	if (setXoscProccessDigest() == 0)//success
		memcpy(pbBuffer + 0x60, xbox::keyvault::data::proccessDigest, 0x10);

	xbox::utilities::writeFile("XeOnline:\\XOSC.bin", pbBuffer, cbBuffer);
	return 0;
}