#include "stdafx.h"
#include "Xosc.h"

// For ID: 9, V: 2

extern DWORD dwHvKeysStatusFlags;
extern WORD wBldrFlags;

extern BOOL RunningFromUSB;
extern KEY_VAULT_DATA keyVault;
extern XEX_EXECUTION_ID spoofedExecutionId;


#define XOSC_VER_MAJOR	9
#define XOSC_VER_MINOR	2

#define BLDR_FLAGS_BASE	0xD83E
#define BLDR_FLAGS_KV1	~0x20

#define CRL_VERSION	6

#define HARDWARE_INFO_FLAGS_BASE		0x40000207
#define HARDWARE_INFO_FLAGS_BASE_KV1	0x00000207

#define HV_KEYS_STATUS_FLAGS			0x23289D3
#define HV_KEYS_STATUS_FLAGS_CRL		0x10000
#define HV_KEYS_STATUS_FLAGS_FCRT		 0x1000000

const QWORD HV_PROTECTED_FLAGS_AUTH_EX_CAP = 4;
const QWORD HV_PROTECTED_FLAGS_DISC_AUTH = 2;
const QWORD HV_PROTECTED_FLAGS_NO_EJECT_REBOOT = 1;
const QWORD HV_PROTECTED_FLAGS_NONE = 0;

#define XOSC_PCI_VALUE				0x40000012

#define XOSC_FLAG_BASE				0x2BB
#define XOSC_FLAG_EXE				0x04
#define XOSC_FLAG_NEW_IDENTIFIERS	0x40
#define XOSC_FLAG_SHOULD_EXIT		0x2000000000000000
#define XOSC_FLAG_TERM_PENDING		0x4000000000000000

#define XOSC_FOOTER					0x5F534750


#define SHA_USE_STATIC	1 // comment this out to allow dumper to work
// #define TIME_USE_STATIC	1 // comment this out to use real system time

BYTE xoscbufData[0x8000]; // xosc uses xam alloc instead!!
PVOID xoscbuf = (VOID*)xoscbufData;
DWORD xoscbufsz;

NTSTATUS getPciBridgeInfo(void* r3, void* r4, void* r5, RESPONSE_DATA* resp);
NTSTATUS getStorageSizes(void* r3, void* r4, void* r5, RESPONSE_DATA* resp);
NTSTATUS getSecurityInfo(void* r3, void* r4, void* r5, RESPONSE_DATA* resp);
NTSTATUS getMediaInfoCheck(RESPONSE_DATA* resp);
NTSTATUS getHvHddCheckData(RESPONSE_DATA* resp);
NTSTATUS getHvIdCacheData(RESPONSE_DATA* resp);

NTSTATUS getXeikaOsig(void* r3, void* r4, void* r5, RESPONSE_DATA* resp);
//NTSTATUS dvdGetInquiryData(void* r3, void* r4, void* r5, RESPONSE_DATA* resp);
void getCurrentTimeJuggled(WORD* outbuf);


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

DWORD CreateXOSCBuffer(void* r3, void* r4, void* r5, RESPONSE_DATA* resp, DWORD respSz) {

	DbgPrint("Calculating XOSC response..\r\n");
	// Clear the buffer
	ZeroMemory(resp, respSz);



	//typedef NTSTATUS (*XOSCFUNCALL)(void* r3, void* r4, void* r5, RESPONSE_DATA* resp, DWORD respSz);
	//XOSCFUNCALL OXSC_Export001 = (XOSCFUNCALL)(DWORD)(0x90015BD0&0xFFFFFFFF);

	//XOSCFUNCALL xoscEntry = (XOSCFUNCALL)(*(DWORD*)(0x90015BD0&0xFFFFFFFF));
	//Run real xosc first..
	//xoscEntry(r3, r4, r5, resp, respSz);

	resp->XboxHardwareInfoFlags = XboxHardwareInfo->Flags;
	BYTE moboSerialByte = 0;

	moboSerialByte = (((char2byte(keyVault.Data.ConsoleCertificate.ConsolePartNumber[2]) << 4) & 0xF0) | ((char2byte(keyVault.Data.ConsoleCertificate.ConsolePartNumber[3]) & 0x0F)));
	DWORD mval = 0;//((resp->XboxHardwareInfoFlags & 0x20)>>28)&0xF;

	//DbgPrint("Got Mobo Serial Byte: %02X", moboSerialByte);

	//0xF0000000 system type
	//(0=xenon, 1=zephyr, 2= falcon, 3=jasper, 4=trinity, 5=corona, 6=winchester, ?7?=ridgeway)

	if (moboSerialByte < 0x10) //Xenon
		mval = 0;
	else if (moboSerialByte < 0x14) //Zephyr
		mval = 1;
	else if (moboSerialByte < 0x18) //Falcon
		mval = 2;
	else if (moboSerialByte < 0x52) //Jasper
		mval = 3;
	else if (moboSerialByte < 0x58) //Trinity (might be 50, idk)
		mval = 4;
	else /*if(moboSerialByte<0x70)*/ //Corona
		mval = 5;

	resp->XboxHardwareInfoFlags = (resp->XboxHardwareInfoFlags & 0x0FFFFFFF) | ((mval & 0xF) << 28);


	// Fill in request
	//SERVER_XOSC_REQUEST request;
	//memcpy(request.SessionKey, Connection.seshKey, 16);
	//request.Crl = Challenge.crl;
	//request.Fcrt = Challenge.fcrt;
	//request.Type1Kv = Challenge.type1KV;
	//XEX_EXECUTION_ID* pCurrentExecutionId;// = challenge.pCurrentExecutionId;

	//request.Motherboar = mval;

	//if ((request.ExecutionIdResult = XamGetExecutionId(&pCurrentExecutionId)) == S_OK)
	//{
	//	memcpy(&request.ExecutionId, pCurrentExecutionId, sizeof(XEX_EXECUTION_ID));
	//}
	//request.HvProtectedFlags = HvSecurityInfoCache->hvProtectedFlagsCopy;

	////Get access to network
	//CritSections.getServerAccess();
	//RtlEnterCriticalSection(&CritSections.ChallengeLock);

	//// Send our request and get our response
	//if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_XOSC, (BYTE*)&request, sizeof(SERVER_XOSC_REQUEST), resp, sizeof(RESPONSE_DATA)) != ERROR_SUCCESS)
	//{
	//	DbgPrint("CreateXOSCBuffer - SendCommand failed");
	//	XNotifyUI(L"An error occurred in NiNJA (SVCSRVCF), restarting...");
	//	Sleep(8000);
	//	HalReturnToFirmware(HalFatalErrorRebootRoutine);
	//	RtlLeaveCriticalSection(&CritSections.challengeLock);
	//	CritSections.releaseServer();
	//	return E_FAIL;
	//}
	//RtlLeaveCriticalSection(&CritSections.challengeLock);
	//CritSections.releaseServer();

	NTSTATUS ret = STATUS_SUCCESS;

	if ((resp == NULL) || (respSz == 0))
		ret = 0x80004005;
	else if (respSz < sizeof(RESPONSE_DATA))
		ret = 0x80070057;
	else
	{
		DWORD dwRes = 0;
		//memset(resp, 0, respSz);
		//memset(resp, 0xAA, sizeof(RESPONSE_DATA));
		//resp->respMagic = 0x5F534750; // '_SGP'
		resp->flags = 0ULL;
		//resp->verMaj = 9;
		//resp->verMin = 2;

		//Call random sleep
		/*DWORD dwRand;
		XeCryptRandom((BYTE*)&dwRand, 4);
		dwRand = (dwRand%0xA)+0xA;
		Sleep(dwRand);*/


		//Get storage Sizes
		//TODO;	Make the return values match whats in the keyvault

		//if (!Challenge.type1KV)
			getStorageSizes(r3, r4, r5, resp);

		//DbgPrint("XOSC: XboxHardwareInfoFlags: %08X", resp->XboxHardwareInfoFlags);

		//Get ExecutionID
		PXEX_EXECUTION_ID xid;
		if (NT_SUCCESS(resp->ExecIdResp = XamGetExecutionId(&xid)))
		{
			//Spoof TitleID and MediaID to dash if it looks weird
			if (xid->TitleID == 0 || xid->TitleID == 0xFFFFFFFF || xid->MediaID == 0xFFFFFFFF || xid->TitleID == 0xFFFF0055 || xid->TitleID == 0xFFFE07FF){

				DWORD const DW_ZERO = 0x00000000;
				spoofedExecutionId.TitleID = 0xFFFE07D1;
				memcpy(&xid, &spoofedExecutionId, sizeof(XEX_EXECUTION_ID));

				memcpy(&resp->dwMediaType, DW_ZERO, sizeof(DWORD));//Not sure what the right value should be here
				memcpy(&resp->dwTitleId, &spoofedExecutionId.TitleID, sizeof(DWORD));


			}
			else{
				memcpy(&resp->xid, xid, sizeof(XEX_EXECUTION_ID));
				XamLoaderGetMediaInfo(&resp->dwMediaType, &resp->dwTitleId);
			}
			resp->flags |= XOSC_MEDIA_INQUIRY_FLAG;
		}

		//dvdGetInquiryData(r3, r4, r5, resp); //Get xeika from dvd
		//getXeikaOsig(r3, r4, r5, resp); //Get xeika from kv
		resp->flags |= XOSC_DVD_INQUIRY_FLAG;
		resp->flags |= XOSC_XEIKA_INQUIRY_FLAG;
		getPciBridgeInfo(r3, r4, r5, resp); //Get PCIBridge and HardwareInfo (probably to fish out jtags)
		getSecurityInfo(r3, r4, r5, resp); //Check mediaType, HddInfo, dvd info

		if (XamLoaderIsTitleTerminatePending())
		{
			resp->flags |= 0x4000000000000000ULL; // (1<<62)
			resp->dwResult = 0;
		}
		//if(XamTaskShouldExit())
		//{
		//	 resp->flags |= 0x2000000000000000ULL; // (1<<61)
		//	 resp->dwResult = 0;
		//}

		resp->dwResult = dwRes;
		ret = STATUS_SUCCESS;
	}

	// Make sure some important server sided values aren't zero
	if (resp->zeroEncryptedConsoleType == 0 || resp->xexHashing == 0 || resp->hvHeaderFlags == 0 || resp->hvKeyStatus == 0)
	{
		DbgPrint("CreateXOSCBuffer - Sanity check failed");
		XNotifyUI(L"An error occurred. Please mention \"XOSCFAIL\" to NiNJA Support");
		Sleep(7000);
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return 0;
	}


#if defined(DUMP_XOSC_BUFFER)
	// We want to dump our xosc buffer to compare
	//DebugBreak();
	if (CWriteFile(RunningFromUSB ? PATH_XOSC_DUMP_USB : PATH_XOSC_DUMP_HDD, resp, respSz) == FALSE)
	{
		DbgPrint("CreateXOSCBuffer - Failed to dump XOSC buffer");
	}
	else
	{
		DbgPrint("CreateXOSCBuffer - Dumped XOSC Buffer");
	}
	//Sleep(3000); // Allow time for the write flush
	//HalReturnToFirmware(HalResetSMCRoutine);
#endif

	DbgPrint("XOSC spoofed.");
	return (DWORD)ret;
}

//void getCurrentTimeJuggled(WORD* outbuf)
//{
//
//	FILETIME ftim;
//	TIME_FIELDS tfs;
//#ifdef TIME_USE_STATIC
//	FakeSystemTime(&ftim);
//#else
//	KeQuerySystemTime(&ftim);
//#endif
//	RtlTimeToTimeFields(&ftim, &tfs);
//	outbuf[0] = tfs.Year; // 0
//	outbuf[1] = tfs.Month; // 2
//	outbuf[2] = tfs.Weekday; // 4
//	outbuf[3] = tfs.Day; // 6
//	outbuf[4] = tfs.Hour; // 8
//	outbuf[5] = tfs.Minute; // A
//	outbuf[6] = tfs.Second; // C
//	outbuf[7] = tfs.Milliseconds; // E
//}

NTSTATUS getPciBridgeInfo(void* r3, void* r4, void* r5, RESPONSE_DATA* resp)
{
	ULARGE_INTEGER ulres;
	BYTE buf[0x100];
	PPCI_CONF_HDR pch = (PPCI_CONF_HDR)buf;
	memset(buf, 0, 0x100);
	HalReadWritePCISpace(0, 2, 0, 0, buf, 0x100, 0); // display controller device, kernel makes same call first thing in VdDetectSystemType
	resp->flags |= XOSC_PCI_INQUIRY_FLAG;
	resp->HardwareMaskTemplate = 0x40000012;

	ulres.HighPart = ((pch->ClassBase & 0xFF) | ((pch->VendorID << 8) & 0xFFFF00)) << 8;
	ulres.HighPart |= XboxHardwareInfo->PCIBridgeRevisionID & 0xFF;
	ulres.LowPart = ((pch->RevisionID & 0xFF) | ((pch->Status << 8) & 0xFFFF00)) << 8;
	ulres.LowPart |= pch->ClassIf & 0xFF;

	resp->HardwareMask = ulres.QuadPart;
	return STATUS_SUCCESS;
}


static STRING CdRomString = { 0xE, 0xF, "\\Device\\Cdrom0" };

NTSTATUS getLowPartAllocationUnits(char* device, PDWORD dest)
{
	NTSTATUS ret = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oab;
	IO_STATUS_BLOCK iosb;
	STRING lstr;
	HANDLE fhand;
	*dest = 0;
	RtlInitAnsiString(&lstr, device);
	oab.RootDirectory = NULL;
	oab.Attributes = 0x40;
	oab.ObjectName = &lstr;
	if (NT_SUCCESS(NtOpenFile(&fhand, 0x100001, &oab, &iosb, 1, 0x800021)))
	{
		FILE_FS_SIZE_INFORMATION fsinfo;
		if (NT_SUCCESS(ret = NtQueryVolumeInformationFile(fhand, &iosb, &fsinfo, sizeof(FILE_FS_SIZE_INFORMATION), FileFsSizeInformation)))
		{
			*dest = fsinfo.TotalAllocationUnits.LowPart;
		}
		NtClose(fhand);
	}
	return ret;
}

NTSTATUS getStorageSizes(void* r3, void* r4, void* r5, RESPONSE_DATA* resp)
{
	resp->flags |= XOSC_STORAGE_INQUIRY_FLAG;
	getLowPartAllocationUnits("\\Device\\Mu0\\", &resp->Mu0Au);
	getLowPartAllocationUnits("\\Device\\Mu1\\", &resp->Mu1Au);
	getLowPartAllocationUnits("\\Device\\BuiltInMuSfc\\", &resp->SfcAu);
	getLowPartAllocationUnits("\\Device\\BuiltInMuUsb\\Storage\\", &resp->IntMuAu);
	getLowPartAllocationUnits("\\Device\\Mass0PartitionFile\\Storage\\", &resp->UsbMu0);
	getLowPartAllocationUnits("\\Device\\Mass1PartitionFile\\Storage\\", &resp->UsbMu1);
	getLowPartAllocationUnits("\\Device\\Mass2PartitionFile\\Storage\\", &resp->UsbMu2);
	return STATUS_SUCCESS;
}

/*
NTSTATUS dvdGetInquiryData(void* r3, void* r4, void* r5, RESPONSE_DATA* resp)
{
	PDEVICE_OBJECT pdev;
	NTSTATUS ret = STATUS_SUCCESS; // returned from function
	NTSTATUS rret; // placed into response struct
	rret = ObReferenceObjectByName(&CdRomString, 0, 0, 0, (PVOID*)&pdev);
	if(NT_SUCCESS(rret))
	{
		resp->flags |= XOSC_DVD_INQUIRY_FLAG;
		SCSI_PASS_THROUGH_DIRECT cmd;
		DbgPrint("dvd object referenced ok, making ioctl\n");
		memset(&cmd, 0, sizeof(SCSI_PASS_THROUGH_DIRECT));
		memset(resp->DvdInqRespData, 0xFF, DVD_INQUIRY_RESPONSE_SIZE);
		cmd.DataBuffer = resp->DvdInqRespData;
		cmd.DataTransferLength = sizeof(SCSI_PASS_THROUGH_DIRECT);
		cmd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
		cmd.DataIn = 1;
		cmd.Cdb[0] = SCSI_CMD_FORMAT_INQUIRY;
		cmd.Cdb[4] = sizeof(SCSI_PASS_THROUGH_DIRECT);
		cmd.Cdb[5] = 0xC0;
		rret = IoSynchronousDeviceIoControlRequest(0x4D014, pdev, &cmd, sizeof(SCSI_PASS_THROUGH_DIRECT), NULL, 0, NULL);
		DbgPrint("ioctl returned 0x%x\n", rret);
		ObDereferenceObject(pdev);

	}
	else
	{
		//memset(resp->DvdInqRespData, 0xAA, sizeof(resp->DvdInqRespData));

		DbgPrint("dvd object ref fail 0x%x\n", rret);
		ret = rret;
	}
	resp->DvdInqResp = rret;
	return ret;
}*/

/*
XEIKA_DATA xdat;
NTSTATUS getXeikaOsig(void* r3, void* r4, void* r5, RESPONSE_DATA* resp)
{
	NTSTATUS ret;
	DWORD keylen;
	memset(&xdat, 0x0, sizeof(XEIKA_DATA));
	keylen - sizeof(XEIKA_DATA);
	//keylen - XeKeysGetKeyProperties(XEKEY_XEIKA_CERTIFICATE); // 0x1388 in size??
	DbgPrint("keylen 0x%x sizeof 0x%x resp 0x%x xdat 0x%x\n", keylen, sizeof(XEIKA_DATA), resp, &xdat);
	ret = XeKeysGetKey(XEKEY_XEIKA_CERTIFICATE, &xdat, &keylen);
	if(NT_SUCCESS(ret))
	{
		if((keylen <= 0x110||(xdat.Signature != XEIKA_DATA_SIGNATURE)||(xdat.Version != XEIKA_DATA_VERSION))
			ret = STATUS_INVALID_PARAMETER_1;
		else
		{
			resp->flags |= XOSC_XEIKA_INQUIRY_FLAG;
			memcpy(resp->XeikaInqData, xdat.OddData.InquiryData, DVD_INQUIRY_RESPONSE_SIZE);
			resp->DvdXeikaPhaseLevel = xdat.OddData.PhaseLevel;
		}
	}
	resp->XeikaInqResp = ret;
	return ret;
}*/


NTSTATUS getHvIdCacheData(RESPONSE_DATA* resp)
{
	NTSTATUS ret = STATUS_SUCCESS;
	int failcnt = 0;
	BYTE* buf = (BYTE*)xoscbuf;
	PCONSOLE_ID_HASH_CACHE ich = (PCONSOLE_ID_HASH_CACHE)xoscbuf;
	BYTE hashBuf[0x14];
	while (failcnt < 5)
	{
		memcpy(buf, HvIdHashCache, sizeof(CONSOLE_ID_HASH_CACHE));
		XeCryptSha(&buf[0x14], sizeof(CONSOLE_ID_HASH_CACHE) - 0x14, NULL, 0, NULL, 0, hashBuf, 0x14);

		if (memcmp(hashBuf, buf, 0x14) == 0) // they use a byte load and subtract loop here instead of memcmp, but could just be compiler optimization
		{
			failcnt = 5; // break while()
		}
		else
		{
			failcnt++;
			if (failcnt == 5)
			{
				resp->HvIdCacheDataResp = 0xC8003003; //TODO: See what happens if we comment this out
				return 0xC8003003;
			}
		}
	}
	// the signature check succeeded to get here
	if (buf == NULL) // a bit belated, the code(r) must be rather retarded
	{
		ret = 0xC8003003;
	}
	else if (ich->dwHashUpdateCount >= 1)
	{
		DWORD keysz = 0xC;
		//keysz = XeKeysGetProperties(XEKEY_CONSOLE_SERIAL_NUMBER);

		BYTE keybuf[0xC];
		memcpy(keybuf, keyVault.Data.ConsoleSerialNumber, 0xC);

		DWORD i;
		DWORD cnt = ich->dwHashUpdateCount - 1; // this is usually just 1
		if (cnt > 5)
			cnt = 5;
		resp->ConsoleId[0] = ich->cId.consoleIdAsQw;
		resp->flags |= XOSC_SERIAL_INQUIRY_FLAG;
		if (cnt != 0)
		{
			QWORD* dest = &resp->ConsoleId[0];
			QWORD* src = &ich->cId.consoleIdAsQw;
			for (i = 0; i < cnt; i++)
			{
				dest[i + i] = src[i + 2];
			}
		}
		if (cnt < 5) // zero remaining entries
		{
			for (i = cnt; i < 5; i++)
			{
				resp->ConsoleId[i + 1] = 0ULL;
			}
		}
		memcpy(resp->ConsoleSerial, keybuf, 0xC); // copy console serial from xekeys response
		resp->ConsoleSerial[0xC] = 0; // set the last byte to 0
		ret = STATUS_SUCCESS;
	}
	else
		ret = 0xC8003005;

	resp->HvIdCacheDataResp = ret;
	return STATUS_SUCCESS; // // always returns 0
}

NTSTATUS getHvHddCheckData(RESPONSE_DATA* resp)
{
	resp->flags |= XOSC_HDD_INQUIRY_FLAG;
	if (resp->XboxHardwareInfoFlags & 0x20) // this bit signals HDD is present
	{
		BYTE hashbuf[0x14];
		XECRYPT_RSAPUB_2048 rsaKey;
		DWORD rsaKeySz = sizeof(XECRYPT_RSAPUB_2048);
		int failcnt = 0;
		BYTE* buf = (BYTE*)xoscbuf;
		PHDD_SECURITY_BLOB hdb = (PHDD_SECURITY_BLOB)resp;
		memset(resp->HddSerialNumber, 0, 0x48); // memset resp hdd info from 0x1D4 for 0x48 bytes
		while (failcnt < 5) // it will try to check the sig 5 times
		{
			memcpy(buf, HvHddSecurityBlobCache, sizeof(HDD_SECURITY_BLOB));
			XeCryptSha(buf, sizeof(HDD_SECURITY_BLOB) - 0x100, NULL, 0, NULL, 0, hashbuf, 0x14);
			if (NT_SUCCESS(XeKeysGetKey(XEKEY_CONSTANT_SATA_DISK_SECURITY_KEY, &rsaKey, &rsaKeySz)))
			{
				if ((rsaKeySz == sizeof(XECRYPT_RSAPUB_2048)) && (rsa.Key.Rsa.cqw == 0x20))
				{
					XeCryptBnQw_SwapDwQwLeBe((PQWORD)(hdb->Signature), (PQWORD)(hdb->Signature), 0x20);
					if (XeCryptBnQwNeRsaPubCrypt((PQWORD)(hdb->Signature), (PQWORD)(hdb->Signature), &rsaKey.Rsa) != 0)
					{
						XeCryptBnQw_SwapDwQwLeBe((PQWORD)(hdb->Signature), (PQWORD)(hdb->Signature), 0x20);
						if (XeCryptBnDwLePkcs1Verify(hashbuf, hdb->Signature, 0x100) != 0)
						{
							if (buf != NULL) // again a little late/retarded with this...
							{
								memcpy(resp->HddSerialNumber, hdb->SerialNumber, 0x14);
								memcpy(resp->HddFirmwareRevision, hdb->FirmwareRevision, 0x8);
								memcpy(resp->HddModelNumber, hdb->ModelNumber, 0x28);
								resp->HddUserAddressableSectors = hdb->UserAddressableSectors;
							}
							failcnt = 5; // break while loop
						}
						else{
							memset(resp->HddSerialNumber, 0xAA, 0x48);// return it to the way it was before we decided there was an hdd
							resp->XboxHardwareInfoFlags = resp->XboxHardwareInfoFlags &~0x20;
						 // zero the sector size too
						 // make sure this happens before anything else that uses 0x20 flag
							return STATUS_SUCCESS;
						}
					}
				}
			}
			failcnt++;
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS getMediaInfoCheck(RESPONSE_DATA* resp)
{
	NTSTATUS ret = STATUS_SUCCESS;
	int failcnt = 0;
	BYTE hashbuf[0x14];
	MEDIA_INFO_CACHE mic;
	memset(&mic, 0, sizeof(MEDIA_INFO_CACHE)); // they do this with 2 memsets, 0x13(plus manual byte) + 0x8C
	while (failcnt < 5) // it will try to check the hash 5 times
	{
		memcpy(&mic, HvMediaInfoCache, sizeof(MEDIA_INFO_CACHE));
		XeCryptSha((PBYTE)&mic.dwUnk1, sizeof(MEDIA_INFO_CACHE) - 0x14, NULL, 0, NULL, 0, hashbuf, 0x14); // hash everything after the hash
		if (memcmp(hashbuf, mic.abSha, 0x14) == 0) // they use a byte load and subtract loop here instead of memcmp, but could just be compiler optimization
		{
			failcnt = 5; // break while()
		}
		else
		{
			failcnt++;
			if (failcnt == 5)
			{
				resp->MediaInfoResp = 0xC8003003;
				return 0xC8003003; //TODO: Check what happens if you comment this...
			}
		}
	}
	// the sha check succeeded to get here
	resp->flags |= XOSC_MEDIA_INQUIRY_FLAG;
	memcpy(resp->unkMediaInfo, HvSecurityInfoCache->hvMediaInfoUnk80, 0x80); // stil not sure what this buffer actually holds

	resp->MediaInfodwUnk1 = mic.dwUnk1;
	resp->MediaInfodwUnk2 = mic.dwUnk2;
	resp->MediaInfoAbUnk = mic.bUnk.abUnkAsDword;
	resp->MediaInfoPad5 = mic.pad5;
	resp->DvdDmil10Data = mic.Dmil0Data;
	resp->MediaInfoUnkp3 = mic.dwUnkp3;
	resp->Layer0PfiSectors = (QWORD)(mic.HvLayer0PfiSectors & 0xFFFFFFFF);
	resp->Layer1PfiSectors = (QWORD)(mic.HvLayer1PfiSectors & 0xFFFFFFFF);

	memcpy(resp->DvdPfiInfo, mic.abPfi, 0x11); // they copy 1 byte + PFI byte from cache.. weird
	memcpy(resp->DvdDmiMediaSerial, mic.DmiMediaSerial, 0x20); // seems at least 4 bytes of the 'padding' is useful
	memcpy(resp->DvdMediaId1, mic.MediaId1, 0x10);

	resp->DvdGeometry.Sectors = mic.dvdGeom.Sectors; // they actually copy this with a ld and sd
	resp->DvdGeometry.BytesPerSector = mic.dvdGeom.BytesPerSector;
	memcpy(resp->DvdMediaId2, mic.MediaId2, 0x10); // they manually copy this with ld/sd twice
	resp->DvdUnkp1 = mic.dwUnkp1;

	resp->MediaInfoResp = ret;
	return STATUS_SUCCESS; // always returns 0
}

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


typedef struct _SMC_VER_SPOOF{
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

//VOID loadXOSC(){
//	XexLoadImageFromMemory(XOSCImage, XOSCImageSize, XOSCImageName, XOSCLoadFlags, XOSCVersion, (PHANDLE)XOSCModuleHandle);
//}

HRESULT getSecurityInfo(void* r3, void* r4, void* r5, RESPONSE_DATA* resp)
{
	HANDLE modHand;
	WORD tval = 0;
	PLDR_DATA_TABLE_ENTRY ldat;
	BYTE hashbuf[0x14];
	WORD time[8];
	BYTE smcCmd[0x10];
	BYTE smcResp[0x10];
	memset(smcCmd, 0, 0x10);
	memset(smcResp, 0, 0x10);
	resp->flags |= XOSC_SECURITY_INQUIRY_FLAG;
	//getCurrentTimeJuggled(time);
	memset(time, 0, 16);
	time[7] = time[7] & 0xF8;

	
	//resp->hvHeaderFlags = HvSecurityInfoCache->headerFlags;
	//resp->hvUnrestrictedPrivs = HvSecurityInfoCache->UnrestrictedPrivs;
	//resp->kvOddFeatures = HvSecurityInfoCache->kvOddFeatures;
	resp->hvUnknown = HvSecurityInfoCache->dwUnk1;
	resp->kvPolicyFlashSize = /*Challenge.type1KV ? 0 : */keyVault.Data.PolicyFlashSize; //HvSecurityInfoCache->kvPolicyFlash;
	//resp->kvRestrictedStatus = HvSecurityInfoCache->hvRestrictedStatus;
	//resp->hvKeyStatus = HvSecurityInfoCache->keyStatus;
	resp->kvRestrictedPrivs = 0; //HvSecurityInfoCache->kvRestrictedPrivs;
	resp->hvSecurityDetected = 0; //HvSecurityInfoCache->secdataSecurityDetected;
	resp->hvSecurityActivated = 0; //HvSecurityInfoCache->secdataSecurityActivated;
	//resp->hvProtectedFlags = HV_PROTECTED_FLAGS_AUTH_EX_CAP | ((*(QWORD*)0x8E038678) & HV_PROTECTED_FLAGS_NO_EJECT_REBOOT); //HvSecurityInfoCache->hvProtectedFlagsCopy;
	resp->secDataDvdBootFailures = 0; //HvSecDataPartCopy->dwDvdBootFailures;
	resp->secDataFuseBlowFailures = 0; //HvSecDataPartCopy->dwFuseBlowFailures;
	resp->secDataDvdAuthExFailures = 0; //HvSecDataPartCopy->dwDvdAuthExFailures;
	resp->secDataDvdAuthExTimeouts = 0; //HvSecDataPartCopy->dwDvdAuthExTimeouts;
	resp->crlVersion = CRL_VERSION; //HvCrlCache->DataHeader.Version;

	XeCryptSha(keyVault.cpuKey, 0x10, NULL, NULL, NULL, NULL, resp->hvCpuKeyHash, XECRYPT_SHA_DIGEST_SIZE);
	//memcpy(resp->hvCpuKeyHash, HvKeyInfo->HvCpuKeyShaCache, 0x10);
	//memcpy(resp->hvCpuKeyHash, cpuKeyDigest, 0x10);


	memcpy(hashbuf, keyVault.kvDigest, 0x10); // this overflows HvKvHmacShaCache into HvZeroEncryptedWithConsoleType by 4 bytes
	memcpy(hashbuf + 0x10, resp->zeroEncryptedConsoleType, 4);

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
			binToFile("HDD:\\xam_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

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
				binToFile("HDD:\\kern_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));


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

			mval = ((resp->XboxHardwareInfoFlags) >> 28) & 0xF;
			memcpy(smcResp, smcVers[mval].smcVer, 4); // this will clean things up for jtags (mostly, see xenon/zephyr comment) and leave the async info byte intact
			for (int i = 0; i < 4; i++) { smcResp[i] ^= 0xFF; } //unobfuscate

			XEX_EXECUTION_ID* pExecutionId;
			XamGetExecutionId(&pExecutionId);

			if (pExecutionId->TitleID == 0xFFFE07D1) // if is dash or if we are spoofing as dash..
			{
				XECRYPT_SHA_STATE xsha;

				XeCryptShaInit(&xsha);
				XeCryptShaUpdate(&xsha, btmp, arg1len);


				if ((resp->XboxHardwareInfoFlags & 0x20) == 0x20)
					//memcpy(&xsha, dashShaHasHdd, sizeof(XECRYPT_SHA_STATE));
					CWriteFile("XeOnline:\\dash_sha_hdd.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));
				else
					//memcpy(&xsha, dashSha, sizeof(XECRYPT_SHA_STATE));
					CWriteFile("XeOnline:\\dash_sha.bin", (char*)&xsha, sizeof(XECRYPT_SHA_STATE));

				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaFinal(&xsha, hashbuf, 0x14);
			}
			else{ // Use our clean xex hash if not on dash
				XECRYPT_SHA_STATE xsha;
				memcpy(&xsha, &Challenge.xShaCurrentXex, sizeof(XECRYPT_SHA_STATE));
				XeCryptShaUpdate(&xsha, hashbuf, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaUpdate(&xsha, hashbuf, 0x14);

				//XeCryptSha(btmp, arg1len, hashbuf, 0x14, (BYTE*)smcResp, 0x5, hashbuf, 0x14);
			}
//#endif // SHA_USE_STATIC
			tval |= 4;
		}
	}

	//XexLoadImageFromMemory(XOSCImage, XOSCImageSize, XOSCImageName, XOSCLoadFlags, XOSCVersion, (PHANDLE)XOSCModuleHandle);

	//if (XexLoadImageFromMemory(XOSCImage, XOSCImageSize, XOSCImageName, XOSCLoadFlags, XOSCVersion, (PHANDLE)XOSCModuleHandle)!= 0{
	//	DbgPrint("Failed to load xosc into memory");
	//}


	/*HANDLE hThread;
	DWORD threadId;
	ExCreateThread(&hThread, 0, &threadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)loadXOSC, NULL, CREATE_SUSPENDED);
	//XSetThreadProcessor(hThread, 4);
	SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
	ResumeThread(hThread);*/


	DWORD one, two, three, four;

	SetMemory(&one, (DWORD*)0x90015B6C, sizeof(DWORD));
	SetMemory(&two, (DWORD*)0x90015B4C, sizeof(DWORD));
	SetMemory(&three, (DWORD*)0x90015B68, sizeof(DWORD));
	SetMemory(&four, (DWORD*)0x90015B48, sizeof(DWORD));

	XeCryptSha((PBYTE)(((DWORD)(((one)& 0xFFFF) | ((((two)& 0xFFFF) << 16)))) & 0xFFFFFFFF), (((DWORD)(((three)& 0xFFFF) | ((((four)& 0xFFFF) << 16)))) & 0xFFFFFFFF), hashbuf, 0x14, 0, 0, hashbuf, 0x14);

	hashbuf[0] = (time[7] | tval) & 0xFF;
	memcpy(resp->xexHashing, hashbuf, 0x10);


	getMediaInfoCheck(resp);
	getHvIdCacheData(resp);
	getHvHddCheckData(resp);

	return 0;
}