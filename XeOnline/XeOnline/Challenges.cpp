#include "stdafx.h"

DWORD CreateXKEBuffer(PBYTE pbBuffer, DWORD cbBuffer, PBYTE pbSalt)
{
	ZeroMemory(pbBuffer, cbBuffer);

	// copy over our custom challenge
	memcpy(pbBuffer, global::challenge::bufferAddress, global::challenge::bufferSize);

	// set clean hv address
	*(QWORD*)(pbBuffer + 0x3F8) = 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(global::challenge::cleanHvBuffer);

	// call our custom challenge
	XeKeysExecute(pbBuffer, cbBuffer, MmGetPhysicalAddress(pbSalt), NULL, NULL, NULL);
	
	xbox::utilities::writeFile("XeOnline:\\XKE_PRE.bin", pbBuffer, cbBuffer);

	// DO SHIT HERE

	// dump response
	xbox::utilities::writeFile("XeOnline:\\XKE_POST.bin", pbBuffer, cbBuffer);

	if (!global::challenge::hasChallenged)
	{
		global::challenge::hasChallenged = TRUE;
		xbox::keyvault::data::hvStatusFlags |= 0x10000;
		xbox::utilities::notify(L"XeOnline - Fully Stealthed!");
	}

	return 0;
}

#define SHA_USE_STATIC
DWORD XamLoaderExecuteAsyncChallenge(DWORD dwAddress, DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer)
{
	BYTE falconHash[] = { 0x82, 0xC1, 0xF0, 0x00, 0x9E, 0x79, 0x97, 0xF3, 0x34, 0x0E, 0x01, 0x45, 0x1A, 0xD0, 0x32, 0x57 };
	BYTE jasperHash[] = { 0x55, 0x6A, 0x1A, 0xF9, 0xC6, 0x44, 0x38, 0xE8, 0xC5, 0x50, 0x13, 0x1B, 0x19, 0xF8, 0x2B, 0x0C };
	BYTE coronaHash[] = { 0xD1, 0x32, 0xFB, 0x43, 0x9B, 0x48, 0x47, 0xE3, 0x9F, 0xE5, 0x46, 0x46, 0xF0, 0xA9, 0x9E, 0xB1 };

	ExecuteSupervisorChallenge = (HRESULT(__cdecl *)(DWORD, PBYTE, DWORD, PBYTE, DWORD))dwAddress;
	ExecuteSupervisorChallenge(dwTaskParam1, pbDaeTableName, szDaeTableName, pbBuffer, cbBuffer);

	xbox::utilities::writeFile("XeOnline:\\XOSC_PREB.bin", pbBuffer, cbBuffer);

	memcpy(pbBuffer + 0x50, xbox::keyvault::data::cpuKeyDigest, 0x10);
	memcpy(pbBuffer + 0xF0, pbBuffer + 0x114, 0x24);

	switch (xbox::keyvault::data::consoleType)
	{
	case 0: break;
	case 1: break;
	case 2: memcpy(pbBuffer + 0x70, falconHash, 0x10); break;
	case 3: memcpy(pbBuffer + 0x70, jasperHash, 0x10); break;
	case 4: break;
	case 5: memcpy(pbBuffer + 0x70, coronaHash, 0x10); break;
	default: xbox::utilities::doErrShutdown(L"Currently not supported, sorry!"); break;
	}

	*(BYTE*)(pbBuffer + 0x83) = xbox::keyvault::data::buffer.XeikaCertificate.Data.OddData.PhaseLevel;
	*(WORD*)(pbBuffer + 0x146) = xbox::keyvault::data::bldrFlags;
	*(WORD*)(pbBuffer + 0x148) = xbox::keyvault::data::buffer.GameRegion;
	*(WORD*)(pbBuffer + 0x14A) = xbox::keyvault::data::buffer.OddFeatures;
	*(DWORD*)(pbBuffer + 0x150) = xbox::keyvault::data::buffer.PolicyFlashSize;
	*(DWORD*)(pbBuffer + 0x158) = xbox::keyvault::data::hvStatusFlags;
	*(DWORD*)(pbBuffer + 0x1D0) = xbox::keyvault::data::hardwareFlags;

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

	memcpy(hashbuf, xbox::keyvault::data::keyvaultDigest, 0x10); // this overflows HvKvHmacShaCache into HvZeroEncryptedWithConsoleType by 4 bytes
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
																				 // this is to intercept the shaState state and dump it
			XECRYPT_SHA_STATE xsha;
			XeCryptShaInit(&xsha);
			XeCryptShaUpdate(&xsha, btmp, arg1len);
			writeFile("XeOnline:\\xam_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, (BYTE*)time, 0x10);

			XeCryptShaFinal(&xsha, hashbuf, 0x14);
#else
			// this uses the static predumped shaState state of clean info
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

																					 // this is to intercept the shaState state and dump it
				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				XeCryptShaUpdate(&xsha, btmp, arg1len);
				writeFile("XeOnline:\\kern_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));


				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, (BYTE*)macaddr, 0x6);

				XeCryptShaFinal(&xsha, hashbuf, 0x14);
#else
				// this uses the static predumped shaState state of clean info
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

			mval = ((xbox::keyvault::data::hardwareFlags) >> 28) & 0xF;
			memcpy(smcResp, smcVers[mval].smcVer, 4); // this will clean things up for jtags (mostly, see xenon/zephyr comment) and leave the async info byte intact
			for (int i = 0; i < 4; i++) { smcResp[i] ^= 0xFF; } //unobfuscate

			XEX_EXECUTION_ID* pExecutionId;
			XamGetExecutionId(&pExecutionId);


			XECRYPT_SHA_STATE xsha;

			XeCryptShaInit(&xsha);
			XeCryptShaUpdate(&xsha, btmp, arg1len);


			if ((xbox::keyvault::data::hardwareFlags & 0x20) == 0x20)
				memcpy(&xsha, dashShaHasHdd, sizeof(XECRYPT_SHA_STATE));
			//writeFile("XeOnline:\\dash_sha_hdd.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));
			else
				memcpy(&xsha, dashSha, sizeof(XECRYPT_SHA_STATE));
			//writeFile("XeOnline:\\dash_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

			XeCryptShaUpdate(&xsha, hashbuf, 0x14);
			XeCryptShaUpdate(&xsha, smcResp, 0x5);
			XeCryptShaFinal(&xsha, hashbuf, 0x14);

			if (pExecutionId->TitleID == 0xFFFE07D1) // if is dash or if we are spoofing as dash..
			{
				XECRYPT_SHA_STATE xsha;

				XeCryptShaInit(&xsha);
				XeCryptShaUpdate(&xsha, btmp, arg1len);


				if ((xbox::keyvault::data::hardwareFlags & 0x20) == 0x20)
					memcpy(&xsha, dashShaHasHdd, sizeof(XECRYPT_SHA_STATE));
					//writeFile("XeOnline:\\dash_sha_hdd.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));
				else
					memcpy(&xsha, dashSha, sizeof(XECRYPT_SHA_STATE));
					//writeFile("XeOnline:\\dash_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaFinal(&xsha, hashbuf, 0x14);
			}
			else { // Use our clean xex hash if not on dash
				XECRYPT_SHA_STATE xsha;
				memcpy(&xsha, &global::challenge::xShaCurrentXex, sizeof(XECRYPT_SHA_STATE));
				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaUpdate(&xsha, hashbuf, 0x14);

				//XeCryptSha(btmp, arg1len, hashbuf, 0x14, (BYTE*)smcResp, 0x5, hashbuf, 0x14);
			}

			tval |= 4;
		}
	}

	DWORD one, two, three, four;

	xbox::utilities::setMemory(&one, (DWORD*)0x90015B6C, sizeof(DWORD));
	xbox::utilities::setMemory(&two, (DWORD*)0x90015B4C, sizeof(DWORD));
	xbox::utilities::setMemory(&three, (DWORD*)0x90015B68, sizeof(DWORD));
	xbox::utilities::setMemory(&four, (DWORD*)0x90015B48, sizeof(DWORD));

	XeCryptSha((PBYTE)(((DWORD)(((one)& 0xFFFF) | ((((two)& 0xFFFF) << 16)))) & 0xFFFFFFFF), (((DWORD)(((three)& 0xFFFF) | ((((four)& 0xFFFF) << 16)))) & 0xFFFFFFFF), hashbuf, 0x14, 0, 0, hashbuf, 0x14);

	hashbuf[0] = (time[7] | tval) & 0xFF;
	memcpy(pbBuffer + 0x60, hashbuf, 0x10);


	xbox::utilities::writeFile("XeOnline:\\XOSC_POSTB.bin", pbBuffer, cbBuffer);

	return 0;
}