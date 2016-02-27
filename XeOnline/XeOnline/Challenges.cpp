#include "stdafx.h"

extern KEY_VAULT_DATA keyVault;
extern BYTE sessionKey[];
extern BOOL hasChallenged;
extern BOOL isDevkit;
extern PVOID pSectionHvcData;
extern DWORD pSectionHvcDataSize;

DWORD updateSequence = NULL;
DWORD cTypeFlag = NULL;
DWORD hardwareFlags = NULL;
DWORD hvStatusFlags = 0x23289D3;
WORD bldrFlags = 0xD83E;
CONSOLE_TYPE consoleType = CONSOLE_TYPE_XENON;

BYTE char2byte(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
}

VOID setupSpecialValues(DWORD updSeq)
{
	BOOL hasFcrt = (keyVault.Data.OddFeatures & ODD_POLICY_FLAG_CHECK_FIRMWARE) != 0;
	BYTE moboSerialByte = (((char2byte(keyVault.Data.ConsoleCertificate.ConsolePartNumber[2]) << 4) & 0xF0) | ((char2byte(keyVault.Data.ConsoleCertificate.ConsolePartNumber[3]) & 0x0F)));

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

	if (!hasChallenged)
	{
		hasChallenged = TRUE;
		hvStatusFlags |= 0x10000;
		XNotifyUI(L"XeOnline - Fully Stealthed!");
	}

	return 0;
}
typedef struct _SMC_VER_SPOOF {
	BYTE smcVer[4];
} SMC_VER_SPOOF, *PSMC_VER_SPOOF;
SMC_VER_SPOOF smcVers[] = { // 0=xenon, 1=zephyr, 2=falcon, 3=jasper, 4=trinity, 5=corona, 6=winchester, ?7?=ridgeway
	{ 0xED, 0xED, 0xFE, 0xCB }, // xenon -> sometimes likely refurbs: {0x12, 0x12, 0x1, 0x35}
	{ 0xED, 0xDE, 0xFE, 0xF6 }, // zephyr -> sometimes likely refurbs: {0x12, 0x21, 0x1, 0xD}
	{ 0xED, 0xCE, 0xFE, 0xF9 }, // falcon
	{ 0xED, 0xBE, 0xFD, 0xFC }, // jasper
	{ 0xED, 0xAE, 0xFC, 0xFE }, // trinity
	{ 0xED, 0x9D, 0xFD, 0xFA }, // corona
	{ 0xED, 0x8E, 0xF8, 0xFC }, // winchester
};

unsigned char xamSha[88] = {
	0x00, 0x00, 0x2D, 0x94, 0x9B, 0xB0, 0x90, 0x21, 0xF6, 0xC9, 0x9A, 0xBA, 0x39, 0x43, 0x4D, 0x55,
	0xAE, 0xC2, 0x1A, 0xD1, 0xF6, 0x90, 0xF5, 0x76, 0x81, 0xA7, 0x32, 0x5C, 0x81, 0x5F, 0x0B, 0x38,
	0x81, 0xA7, 0x32, 0x6C, 0x81, 0x5F, 0x0B, 0x3C, 0x81, 0xA7, 0x32, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned char kernSha[88] = {
	0x00, 0x00, 0x00, 0x20, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x98, 0xBA, 0xDC, 0xFE,
	0x10, 0x32, 0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x45, 0x48, 0x32, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x04, 0x0B, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x6D, 0xC0
};

unsigned char dashSha[88] = { // clean dash.xex running from flash (its either or, never both)
	0x00, 0x00, 0x4D, 0xEC, 0xAF, 0x10, 0x04, 0xF5, 0x71, 0x91, 0x70, 0xA3, 0x65, 0xA2, 0xF2, 0x48,
	0x8A, 0x34, 0x8D, 0xC2, 0xD3, 0xEB, 0x77, 0x1C, 0x92, 0x00, 0x10, 0xB8, 0x92, 0x00, 0x10, 0xBC,
	0x92, 0x93, 0xA2, 0xE4, 0x92, 0x00, 0x10, 0xC0, 0x92, 0x93, 0xA2, 0xD4, 0x92, 0x00, 0x10, 0xC4,
	0x92, 0x93, 0xA2, 0xC4, 0x92, 0x00, 0x10, 0xC8, 0x92, 0x93, 0xA2, 0xB4, 0x92, 0x00, 0x10, 0xCC,
	0x92, 0x93, 0xC0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD0
};

unsigned char dashShaHasHdd[88] = { // clean dash.xex running from hdd
	0x00, 0x00, 0x4D, 0xEC, 0xAF, 0x10, 0x04, 0xF5, 0x71, 0x91, 0x70, 0xA3, 0x65, 0xA2, 0xF2, 0x48,
	0x8A, 0x34, 0x8D, 0xC2, 0xD3, 0xEB, 0x77, 0x1C, 0x92, 0x00, 0x10, 0xB8, 0x92, 0x00, 0x10, 0xBC,
	0x92, 0x93, 0xA2, 0xE4, 0x92, 0x00, 0x10, 0xC0, 0x92, 0x93, 0xA2, 0xD4, 0x92, 0x00, 0x10, 0xC4,
	0x92, 0x93, 0xA2, 0xC4, 0x92, 0x00, 0x10, 0xC8, 0x92, 0x93, 0xA2, 0xB4, 0x92, 0x00, 0x10, 0xCC,
	0x92, 0x93, 0xC0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD0
};

#define SHA_USE_STATIC
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
DWORD XamLoaderExecuteAsyncChallenge(DWORD dwAddress, DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer)
{
	BYTE falconHash[] = { 0x82, 0xC1, 0xF0, 0x00, 0x9E, 0x79, 0x97, 0xF3, 0x34, 0x0E, 0x01, 0x45, 0x1A, 0xD0, 0x32, 0x57 };
	BYTE jasperHash[] = { 0x55, 0x6A, 0x1A, 0xF9, 0xC6, 0x44, 0x38, 0xE8, 0xC5, 0x50, 0x13, 0x1B, 0x19, 0xF8, 0x2B, 0x0C };
	BYTE coronaHash[] = { 0xD1, 0x32, 0xFB, 0x43, 0x9B, 0x48, 0x47, 0xE3, 0x9F, 0xE5, 0x46, 0x46, 0xF0, 0xA9, 0x9E, 0xB1 };

	ExecuteSupervisorChallenge_t ExecuteSupervisorChallenge = (ExecuteSupervisorChallenge_t)dwAddress;
	ExecuteSupervisorChallenge(dwTaskParam1, pbDaeTableName, szDaeTableName, pbBuffer, cbBuffer);

	CWriteFile("XeOnline:\\XOSC_PREB.bin", pbBuffer, cbBuffer);

	memcpy(pbBuffer + 0x50, keyVault.cpuKeyDigest, 0x10);
	memcpy(pbBuffer + 0xF0, pbBuffer + 0x114, 0x24);

	switch (consoleType)
	{
	//case CONSOLE_TYPE_XENON: break;
	//case CONSOLE_TYPE_ZEPHYR: break;
	case CONSOLE_TYPE_FALCON: memcpy(pbBuffer + 0x70, falconHash, 0x10); break;
	case CONSOLE_TYPE_JASPER: memcpy(pbBuffer + 0x70, jasperHash, 0x10); break;
	case CONSOLE_TYPE_TRINITY: break;
	case CONSOLE_TYPE_CORONA: memcpy(pbBuffer + 0x70, coronaHash, 0x10); break;// *(QWORD*)(pbBuffer + 0x1A8) = 0x083B5BBDA3000000; *(DWORD*)(pbBuffer + 0x1B0) = 0x0000002A;  *(QWORD*)(pbBuffer + 0x1B8) = 0x6960F25DB1000000; break;
	default: doErrShutdown(L"Currently not supported, sorry!"); break;
	}

	*(BYTE*)(pbBuffer + 0x83) = keyVault.Data.XeikaCertificate.Data.OddData.PhaseLevel;
	*(WORD*)(pbBuffer + 0x146) = bldrFlags;
	*(WORD*)(pbBuffer + 0x148) = keyVault.Data.GameRegion;
	*(WORD*)(pbBuffer + 0x14A) = keyVault.Data.OddFeatures;
	*(DWORD*)(pbBuffer + 0x150) = keyVault.Data.PolicyFlashSize;
	*(DWORD*)(pbBuffer + 0x158) = hvStatusFlags;
	*(DWORD*)(pbBuffer + 0x1D0) = hardwareFlags;

	HANDLE modHand;
	WORD tval = 0;
	PLDR_DATA_TABLE_ENTRY ldat;
	BYTE hashbuf[0x14];
	WORD time[8];
	BYTE smcCmd[0x10];
	BYTE smcResp[0x10];
	memset(smcCmd, 0, 0x10);
	memset(smcResp, 0, 0x10);
	//resp->flags |= XOSC_SECURITY_INQUIRY_FLAG;
	//getCurrentTimeJuggled(time);
	memset(time, 0, 16);
	time[7] = time[7] & 0xF8;

	memcpy(hashbuf, keyVault.kvDigest, 0x10); // this overflows HvKvHmacShaCache into HvZeroEncryptedWithConsoleType by 4 bytes
	memcpy(hashbuf + 0x10, pbBuffer+0x70, 4);

	if (NT_SUCCESS(XexGetModuleHandle("xam.xex", &modHand)))
	{
		PIMAGE_XEX_HEADER xhead;
		ldat = (PLDR_DATA_TABLE_ENTRY)modHand;
		xhead = (PIMAGE_XEX_HEADER)ldat->XexHeaderBase;
		if (xhead != NULL)
		{
			// hashes everything from XEX_SECURITY_INFO.AllowedMediaTypes to end of header, including page permissions and other fun stuff
#ifndef SHA_USE_STATIC
			BYTE* btmp = (BYTE*)(xhead->SecurityInfo + 0x17C);
			DWORD arg1len = xhead->SizeOfHeaders - ((DWORD)btmp - (DWORD)xhead); // header size - offset into header
																				 //XeCryptSha(btmp, arg1len, hashbuf, 0x14, (BYTE*)time, 0x10, hashbuf, 0x14); // this is how its originally done
																				 // this is to intercept the sha state and dump it
			XECRYPT_SHA_STATE xsha;
			XeCryptShaInit(&xsha);
			XeCryptShaUpdate(&xsha, btmp, arg1len);
			CWriteFile("XeOnline:\\xam_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, (BYTE*)time, 0x10);

			XeCryptShaFinal(&xsha, hashbuf, 0x14);
#else
			// this uses the static predumped sha state of clean info
			XECRYPT_SHA_STATE xsha;
			memcpy(&xsha, xamSha, sizeof(XECRYPT_SHA_STATE));

			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, (BYTE*)time, 0x10);

			XeCryptShaFinal(&xsha, hashbuf, 0x14);
#endif
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
				// hashes everything from XEX_SECURITY_INFO.AllowedMediaTypes to end of header, including page permissions and other fun stuff
#ifndef SHA_USE_STATIC
				BYTE* btmp = (BYTE*)(xhead->SecurityInfo + 0x17C);
				DWORD arg1len = xhead->SizeOfHeaders - ((DWORD)btmp - (DWORD)xhead); // header size - offset into header
																					 //XeCryptSha(btmp, arg1len, hashbuf, 0x14, (BYTE*)macaddr, 0x6, hashbuf, 0x14); // this is how its originally done

																					 // this is to intercept the sha state and dump it
				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				XeCryptShaUpdate(&xsha, btmp, arg1len);
				CWriteFile("XeOnline:\\kern_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));


				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, (BYTE*)macaddr, 0x6);

				XeCryptShaFinal(&xsha, hashbuf, 0x14);
#else
				// this uses the static predumped sha state of clean info
				XECRYPT_SHA_STATE xsha;
				memcpy(&xsha, kernSha, sizeof(XECRYPT_SHA_STATE));

				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, (BYTE*)macaddr, 0x6);

				XeCryptShaFinal(&xsha, hashbuf, 0x14);
				tval |= 2;
#endif
			}
			else
				return  ERROR_INVALID_PARAMETER;// STATUS_INVALID_PARAMETER_7;
		}
	}

	// this becomes a little more difficult if we need to spoof this when we are spoofing that dash is running
	if (NT_SUCCESS(XexGetModuleHandle(NULL, &modHand))) // gets the current title handle
	{
		PIMAGE_XEX_HEADER xhead;
		ldat = (PLDR_DATA_TABLE_ENTRY)modHand;
		xhead = (PIMAGE_XEX_HEADER)ldat->XexHeaderBase;
		if (xhead != NULL)
		{
			BYTE mval;
			BYTE* btmp = (BYTE*)(xhead->SecurityInfo + 0x17C);
			WORD arg1len = xhead->SizeOfHeaders - ((DWORD)btmp - (DWORD)xhead); // header size - offset into header
			smcCmd[0] = smc_query_version;
			// this is an example response from trinity: 12 51 03 01 00 00 03 00 00 00 00 00 00 00 00 00
			// the first value itself is always 12 because its a reply to command 12
			// the first 4 values are hardcoded into the smc binary, the fifth and sixth value is something to do with async operation mode
			// the seventh value is only present on trinity or newer smc (not actually used here though) and seems to count up every power up usually by 2
			// until smc is reset via hard reset like power cord disconnect
			//HalSendSMCMessage(smcCmd, smcResp);
			//#ifndef SHA_USE_STATIC
			//			XeCryptSha(btmp, arg1len, hashbuf, 0x14, (BYTE*)smcResp, 0x5, hashbuf, 0x14);
			//#else

			mval = ((hardwareFlags) >> 28) & 0xF;
			memcpy(smcResp, smcVers[mval].smcVer, 4); // this will clean things up for jtags (mostly, see xenon/zephyr comment) and leave the async info byte intact
			for (int i = 0; i < 4; i++) { smcResp[i] ^= 0xFF; } //unobfuscate

			XEX_EXECUTION_ID* pExecutionId;
			XamGetExecutionId(&pExecutionId);


			XECRYPT_SHA_STATE xsha;

			XeCryptShaInit(&xsha);
			XeCryptShaUpdate(&xsha, btmp, arg1len);


			if ((hardwareFlags & 0x20) == 0x20)
				memcpy(&xsha, dashShaHasHdd, sizeof(XECRYPT_SHA_STATE));
			//CWriteFile("XeOnline:\\dash_sha_hdd.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));
			else
				memcpy(&xsha, dashSha, sizeof(XECRYPT_SHA_STATE));
			//CWriteFile("XeOnline:\\dash_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, smcResp, 0x5);
			XeCryptShaFinal(&xsha, hashbuf, 0x14);

			//if (pExecutionId->TitleID == 0xFFFE07D1) // if is dash or if we are spoofing as dash..
			//{
			//	XECRYPT_SHA_STATE xsha;

			//	XeCryptShaInit(&xsha);
			//	XeCryptShaUpdate(&xsha, btmp, arg1len);


			//	if ((hardwareFlags & 0x20) == 0x20)
			//		memcpy(&xsha, dashShaHasHdd, sizeof(XECRYPT_SHA_STATE));
			//		//CWriteFile("XeOnline:\\dash_sha_hdd.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));
			//	else
			//		memcpy(&xsha, dashSha, sizeof(XECRYPT_SHA_STATE));
			//		//CWriteFile("XeOnline:\\dash_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

			//	XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			//	XeCryptShaUpdate(&xsha, smcResp, 0x5);
			//	XeCryptShaFinal(&xsha, hashbuf, 0x14);
			//}
			//else { // Use our clean xex hash if not on dash
			//	XECRYPT_SHA_STATE xsha;
			//	memcpy(&xsha, &Challenge.xShaCurrentXex, sizeof(XECRYPT_SHA_STATE));
			//	XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			//	XeCryptShaUpdate(&xsha, smcResp, 0x5);
			//	XeCryptShaUpdate(&xsha, hashbuf, 0x14);

			//	//XeCryptSha(btmp, arg1len, hashbuf, 0x14, (BYTE*)smcResp, 0x5, hashbuf, 0x14);
			//}
			//#endif // SHA_USE_STATIC
			tval |= 4;
		}
	}

	DWORD one, two, three, four;

	SetMemory(&one, (DWORD*)0x90015B6C, sizeof(DWORD));
	SetMemory(&two, (DWORD*)0x90015B4C, sizeof(DWORD));
	SetMemory(&three, (DWORD*)0x90015B68, sizeof(DWORD));
	SetMemory(&four, (DWORD*)0x90015B48, sizeof(DWORD));

	XeCryptSha((PBYTE)(((DWORD)(((one)& 0xFFFF) | ((((two)& 0xFFFF) << 16)))) & 0xFFFFFFFF), (((DWORD)(((three)& 0xFFFF) | ((((four)& 0xFFFF) << 16)))) & 0xFFFFFFFF), hashbuf, 0x14, 0, 0, hashbuf, 0x14);

	hashbuf[0] = (time[7] | tval) & 0xFF;
	memcpy(pbBuffer + 0x60, hashbuf, 0x10);


	CWriteFile("XeOnline:\\XOSC_POSTB.bin", pbBuffer, cbBuffer);

	return 0;
}