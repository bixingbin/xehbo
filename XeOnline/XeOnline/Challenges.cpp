#include "stdafx.h"

extern KEY_VAULT_DATA keyVault;
extern BYTE sessionKey[];
extern BOOL hasChallenged;
extern BOOL isDevkit;
extern PVOID pSectionHvcData;
extern DWORD pSectionHvcDataSize;

DWORD updateSequence = NULL;
CONSOLE_TYPE consoleType = CONSOLE_TYPE_XENON;
DWORD cTypeFlag = NULL;
DWORD hardwareFlags = NULL;
DWORD hvStatusFlags = 0x23289D3;
WORD bldrFlags = 0xD83E;

VOID setupSpecialValues(DWORD updSeq)
{
	BOOL hasFcrt = (keyVault.Data.OddFeatures & ODD_POLICY_FLAG_CHECK_FIRMWARE) != 0;
	BYTE moboSerialByte = (((keyVault.Data.ConsoleCertificate.ConsolePartNumber[2] << 4) & 0xF0) | (keyVault.Data.ConsoleCertificate.ConsolePartNumber[3] & 0x0F));

	if (hasFcrt)
	{
		hvStatusFlags |= 0x1000000;
		bldrFlags = 0xD81E;
	}

	if (moboSerialByte < 0x10)
	{
		consoleType = CONSOLE_TYPE_XENON;
		cTypeFlag = 0x010C0FFB;
	}
	else if (moboSerialByte < 0x14)
	{
		consoleType = CONSOLE_TYPE_ZEPHYR;
		cTypeFlag = 0x010B0524;
	}
	else if (moboSerialByte < 0x18)
	{
		consoleType = CONSOLE_TYPE_FALCON;
		cTypeFlag = 0x010C0AD8;
	}
	else if (moboSerialByte < 0x52)
	{
		consoleType = CONSOLE_TYPE_JASPER;
		cTypeFlag = 0x010C0AD0;
	}
	else if (moboSerialByte < 0x58)
	{
		consoleType = CONSOLE_TYPE_TRINITY;
		cTypeFlag = 0x0304000D;
	}
	else
	{
		consoleType = CONSOLE_TYPE_CORONA;
		cTypeFlag = 0x0304000E;
	}

	hardwareFlags = (XboxHardwareInfo->Flags & 0x0FFFFFFF) | ((consoleType & 0xF) << 28);
	updateSequence = updSeq;
}



DWORD CreateXKEBuffer(PBYTE pbBuffer, DWORD cbBuffer, PBYTE pbSalt)
{
	ZeroMemory(pbBuffer, cbBuffer);

	HvxPokeDWORD(isDevkit ? 0x60B0 : 0x6148, 0x60000000);
	HvxPokeDWORD(isDevkit ? 0x60E4 : 0x617C, 0x38600001);
	if (isDevkit) HvxPokeDWORD(0x5FF8, 0x48000010);

	MemoryBuffer mbHv;
	CReadFile("XeOnline:\\HV.bin", mbHv);

	PBYTE hvBuff = (PBYTE)XPhysicalAlloc(mbHv.GetDataLength(), MAXULONG_PTR, NULL, PAGE_READWRITE);
	memcpy(hvBuff, mbHv.GetData(), mbHv.GetDataLength());

	// setup console data
	memcpy(hvBuff + 0x20, keyVault.cpuKey, 0x10);
	*(DWORD*)(hvBuff + 0x6) = bldrFlags;
	*(DWORD*)(hvBuff + 0x14) = updateSequence;
	*(DWORD*)(hvBuff + 0x74) = cTypeFlag;

	// copy over our custom challenge
	memcpy(pbBuffer, pSectionHvcData, pSectionHvcDataSize);

	// set clean hv address
	*(QWORD*)(pbBuffer + 0x3F8) = 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(hvBuff);

	// call our custom challenge
	XeKeysExecute(pbBuffer, cbBuffer, MmGetPhysicalAddress(pbSalt), NULL, NULL, NULL);

	// free the hv buffer
	XPhysicalFree(hvBuff);

	CWriteFile("XeOnline:\\XKE.bin", pbBuffer, cbBuffer);
	XNotifyUI(L"XeOnline - Fully Stealthed!");
	return 0;
}


//BYTE XKE_RC4_Key[0x10];
//BYTE BL_Key[0x10] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
//DWORD CreateXKEBuffer(PBYTE pbBuffer, DWORD cbBuffer, PBYTE pbSalt)
//{
//	CWriteFile("XeOnline:\\RETAIL_CHALLENGE.bin", pbBuffer, cbBuffer);
//	XeCryptHmacSha(BL_Key, 0x10, pbBuffer + 0x10, 0x10, NULL, NULL, NULL, NULL, XKE_RC4_Key, 0x10);
//	XeCryptRc4(XKE_RC4_Key, 0x10, pbBuffer + 0x20, 0x03F0 - 0x20);
//	CWriteFile("XeOnline:\\RETAIL_CHALLENGE_DECRYPTED.bin", pbBuffer, cbBuffer);
//
//	HvxPokeDWORD(isDevkit ? 0x60B0 : 0x6148, 0x60000000);
//	HvxPokeDWORD(isDevkit ? 0x60E4 : 0x617C, 0x38600001);
//	if (isDevkit) HvxPokeDWORD(0x5FF8, 0x48000010);
//
//	// clear old challenge and copy ours over
//	ZeroMemory(pbBuffer, cbBuffer);
//	memcpy(pbBuffer, pSectionHvcData, pSectionHvcDataSize);
//
//	MemoryBuffer mbHv;
//	CReadFile("XeOnline:\\HV.bin", mbHv);
//
//	PBYTE hvBuff = (PBYTE)XPhysicalAlloc(mbHv.GetDataLength(), MAXULONG_PTR, NULL, PAGE_READWRITE);
//	memcpy(hvBuff, mbHv.GetData(), mbHv.GetDataLength());
//
//	*(QWORD*)(pbBuffer + 0x3F8) = 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(hvBuff);
//
//	XeKeysExecute(pbBuffer, cbBuffer, MmGetPhysicalAddress(pbSalt), NULL, NULL, NULL);
//
//	XPhysicalFree(hvBuff);
//
//	//*(WORD*)(pbBuffer + 0x2A) = 0x4459;
//	*(WORD*)(pbBuffer + 0x2E) = bldrFlags;
//	*(DWORD*)(pbBuffer + 0x34) = updateSequence;
//	*(DWORD*)(pbBuffer + 0x38) = hvStatusFlags;
//	*(DWORD*)(pbBuffer + 0x3C) = keyVault.Data.ConsoleCertificate.ConsoleType;
//	memcpy(pbBuffer + 0x64, keyVault.cpuKeyDigest, 0x14);
//
//	CWriteFile("XeOnline:\\HVC_RESPONSE.bin", pbBuffer, cbBuffer);
//
//	//XeKeysExecute(pbBuffer, cbBuffer, MmGetPhysicalAddress(pbSalt), pKernelVersion, r7, r8);
//
//	//CWriteFile("XeOnline:\\XKE_PREB.bin", pbBuffer, cbBuffer);
//
//	//SERVER_CHAL_REQUEST chalRequest;
//	//SERVER_CHAL_RESPONSE chalResponse;
//
//	//memcpy(chalRequest.SessionKey, sessionKey, 0x10);
//	//memcpy(chalRequest.Salt, pbSalt, 0x10);
//
//	//if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_XKE_RESP, &chalRequest, sizeof(SERVER_CHAL_REQUEST), &chalResponse, sizeof(SERVER_CHAL_RESPONSE)) != ERROR_SUCCESS)
//	//	doErrShutdown(L"XeOnline - XKESR Error", TRUE);
//
//	//if (chalResponse.Status != XSTL_STATUS_SUCCESS)
//	//	doErrShutdown(L"XeOnline - XKESS Error", TRUE);
//
//	//memcpy(pbBuffer + 0x20, chalResponse.Header, 0x30);
//	//*(WORD*)(pbBuffer + 0x2E) = bldrFlags;
//	//*(DWORD*)(pbBuffer + 0x34) = updateSequence;
//	//*(DWORD*)(pbBuffer + 0x38) = hvStatusFlags;
//
//	//switch (consoleType)
//	//{
//	//case CONSOLE_TYPE_XENON: *(DWORD*)(pbBuffer + 0x3C) = 0x010C0FFB; break;
//	//case CONSOLE_TYPE_ZEPHYR: *(DWORD*)(pbBuffer + 0x3C) = 0x010B0524; break;
//	//case CONSOLE_TYPE_FALCON: *(DWORD*)(pbBuffer + 0x3C) = 0x010C0AD8; break;
//	//case CONSOLE_TYPE_JASPER: *(DWORD*)(pbBuffer + 0x3C) = 0x010C0AD0; break;
//	//case CONSOLE_TYPE_TRINITY: *(DWORD*)(pbBuffer + 0x3C) = 0x0304000D; break;
//	//case CONSOLE_TYPE_CORONA: *(DWORD*)(pbBuffer + 0x3C) = 0x0304000E; break;
//	//}
//
//	//memcpy(pbBuffer + 0x64, keyVault.cpuKeyDigest, 0x14);
//	//memcpy(pbBuffer + 0xFA, chalResponse.hvDigest, 0x6);
//
//	//CWriteFile("XeOnline:\\XKE_POSTB.bin", pbBuffer, cbBuffer);
//
//	if (!hasChallenged)
//	{
//		hvStatusFlags |= 0x10000;
//		hasChallenged = TRUE;
//		XNotifyUI(L"XeOnline - Fully Stealthed!");
//	}
//
//	return 0;
//}
//
//DWORD XamLoaderExecuteAsyncChallenge(DWORD dwAddress, DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer)
//{
//	BYTE falconHash[] = { 0x82, 0xC1, 0xF0, 0x00, 0x9E, 0x79, 0x97, 0xF3, 0x34, 0x0E, 0x01, 0x45, 0x1A, 0xD0, 0x32, 0x57 };
//	BYTE jasperHash[] = { 0x55, 0x6A, 0x1A, 0xF9, 0xC6, 0x44, 0x38, 0xE8, 0xC5, 0x50, 0x13, 0x1B, 0x19, 0xF8, 0x2B, 0x0C };
//	BYTE coronaHash[] = { 0xD1, 0x32, 0xFB, 0x43, 0x9B, 0x48, 0x47, 0xE3, 0x9F, 0xE5, 0x46, 0x46, 0xF0, 0xA9, 0x9E, 0xB1 };
//
//	ExecuteSupervisorChallenge_t ExecuteSupervisorChallenge = (ExecuteSupervisorChallenge_t)dwAddress;
//	ExecuteSupervisorChallenge(dwTaskParam1, pbDaeTableName, szDaeTableName, pbBuffer, cbBuffer);
//
//	CWriteFile("XeOnline:\\XOSC_PREB.bin", pbBuffer, cbBuffer);
//
//	memcpy(pbBuffer + 0x50, keyVault.cpuKeyDigest, 0x10);
//	memcpy(pbBuffer + 0xF0, pbBuffer + 0x114, 0x24);
//
//	switch (consoleType)
//	{
//	//case CONSOLE_TYPE_XENON: break;
//	//case CONSOLE_TYPE_ZEPHYR: break;
//	case CONSOLE_TYPE_FALCON: memcpy(pbBuffer + 0x70, falconHash, 0x10); break;
//	case CONSOLE_TYPE_JASPER: memcpy(pbBuffer + 0x70, jasperHash, 0x10); break;
//	//case CONSOLE_TYPE_TRINITY: break;
//	case CONSOLE_TYPE_CORONA: memcpy(pbBuffer + 0x70, coronaHash, 0x10); break;// *(QWORD*)(pbBuffer + 0x1A8) = 0x083B5BBDA3000000; *(DWORD*)(pbBuffer + 0x1B0) = 0x0000002A;  *(QWORD*)(pbBuffer + 0x1B8) = 0x6960F25DB1000000; break;
//	default: doErrShutdown(L"Currently not supported, sorry!"); break;
//	}
//
//	*(BYTE*)(pbBuffer + 0x83) = keyVault.Data.XeikaCertificate.Data.OddData.PhaseLevel;
//	*(WORD*)(pbBuffer + 0x146) = bldrFlags;
//	*(WORD*)(pbBuffer + 0x148) = keyVault.Data.GameRegion;
//	*(WORD*)(pbBuffer + 0x14A) = keyVault.Data.OddFeatures;
//	*(DWORD*)(pbBuffer + 0x150) = policyFlashSize;
//	*(DWORD*)(pbBuffer + 0x158) = hvStatusFlags;
//	//*(DWORD*)(pbBuffer + 0x1D0) = 0x40000207;
//	*(DWORD*)(pbBuffer + 0x1D0) = XboxHardwareInfo->Flags;
//
//	//setDeviceSize("\\Device\\Mu0\\", pbBuffer + 0x2A8);
//	//setDeviceSize("\\Device\\Mu1\\", pbBuffer + 0x2AC);
//	//setDeviceSize("\\Device\\BuiltInMuSfc\\", pbBuffer + 0x2B0);
//	//setDeviceSize("\\Device\\BuiltInMuUsb\\Storage\\", pbBuffer + 0x2B4);
//	//setDeviceSize("\\Device\\Mass0PartitionFile\\Storage\\", pbBuffer + 0x2B8);
//	//setDeviceSize("\\Device\\Mass1PartitionFile\\Storage\\", pbBuffer + 0x2BC);
//	//setDeviceSize("\\Device\\Mass2PartitionFile\\Storage\\", pbBuffer + 0x2C0);
//
//	CWriteFile("XeOnline:\\XOSC_POSTB.bin", pbBuffer, cbBuffer);
//
//	return 0;
//}