#pragma once
#include "stdafx.h"

typedef struct _XAM_CHAL_RESP {
	BYTE bReserved1[8];                            //0x0
	WORD wHvMagic;                                 //0x8
	WORD wHvVersion;                               //0xA
	WORD wHvQfe;                                   //0xC
	WORD wBldrFlags;                               //0xE
	DWORD dwBaseKernelVersion;                     //0x10
	DWORD dwUpdateSequence;                        //0x14
	DWORD dwHvKeysStatusFlags;                     //0x18
	DWORD dwConsoleTypeSeqAllow;                   //0x1C
	QWORD qwRTOC;                                  //0x20
	QWORD qwHRMOR;                                 //0x28
	BYTE bHvECCDigest[XECRYPT_SHA_DIGEST_SIZE];    //0x30
	BYTE bCpuKeyDigest[XECRYPT_SHA_DIGEST_SIZE];   //0x44
	BYTE bRandomData[0x80];                        //0x58
	WORD hvExAddr;                                 //0xD8 (bits 16-32 of hvex executing addr)
	BYTE bHvDigest[0x6];                           //0xDA (last 6 bytes of first hv hash)
} XAM_CHAL_RESP, *PXAM_CHAL_RESP;

typedef struct _SMC_VER_SPOOF {
	BYTE smcVer[4];
} SMC_VER_SPOOF, *PSMC_VER_SPOOF;

static SMC_VER_SPOOF smcVers[] = { // 0=xenon, 1=zephyr, 2=falcon, 3=jasper, 4=trinity, 5=corona, 6=winchester, ?7?=ridgeway
	{ 0xED, 0xED, 0xFE, 0xCB }, // xenon -> sometimes likely refurbs: {0x12, 0x12, 0x1, 0x35}
	{ 0xED, 0xDE, 0xFE, 0xF6 }, // zephyr -> sometimes likely refurbs: {0x12, 0x21, 0x1, 0xD}
	{ 0xED, 0xCE, 0xFE, 0xF9 }, // falcon
	{ 0xED, 0xBE, 0xFD, 0xFC }, // jasper
	{ 0xED, 0xAE, 0xFC, 0xFE }, // trinity
	{ 0xED, 0x9D, 0xFD, 0xFA }, // corona
	{ 0xED, 0x8E, 0xF8, 0xFC }, // winchester
};

static BYTE xamSha[88] = {
	0x00, 0x00, 0x2D, 0x94, 0x9B, 0xB0, 0x90, 0x21, 0xF6, 0xC9, 0x9A, 0xBA, 0x39, 0x43, 0x4D, 0x55,
	0xAE, 0xC2, 0x1A, 0xD1, 0xF6, 0x90, 0xF5, 0x76, 0x81, 0xA7, 0x32, 0x5C, 0x81, 0x5F, 0x0B, 0x38,
	0x81, 0xA7, 0x32, 0x6C, 0x81, 0x5F, 0x0B, 0x3C, 0x81, 0xA7, 0x32, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static BYTE kernSha[88] = {
	0x00, 0x00, 0x00, 0x20, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x98, 0xBA, 0xDC, 0xFE,
	0x10, 0x32, 0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x58, 0x45, 0x48, 0x32, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x04, 0x0B, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x6D, 0xC0
};

static BYTE dashSha[88] = { // clean dash.xex running from flash (its either or, never both)
	0x00, 0x00, 0x4D, 0xEC, 0xAF, 0x10, 0x04, 0xF5, 0x71, 0x91, 0x70, 0xA3, 0x65, 0xA2, 0xF2, 0x48,
	0x8A, 0x34, 0x8D, 0xC2, 0xD3, 0xEB, 0x77, 0x1C, 0x92, 0x00, 0x10, 0xB8, 0x92, 0x00, 0x10, 0xBC,
	0x92, 0x93, 0xA2, 0xE4, 0x92, 0x00, 0x10, 0xC0, 0x92, 0x93, 0xA2, 0xD4, 0x92, 0x00, 0x10, 0xC4,
	0x92, 0x93, 0xA2, 0xC4, 0x92, 0x00, 0x10, 0xC8, 0x92, 0x93, 0xA2, 0xB4, 0x92, 0x00, 0x10, 0xCC,
	0x92, 0x93, 0xC0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD0
};

static BYTE dashShaHasHdd[88] = { // clean dash.xex running from hdd
	0x00, 0x00, 0x4D, 0xEC, 0xAF, 0x10, 0x04, 0xF5, 0x71, 0x91, 0x70, 0xA3, 0x65, 0xA2, 0xF2, 0x48,
	0x8A, 0x34, 0x8D, 0xC2, 0xD3, 0xEB, 0x77, 0x1C, 0x92, 0x00, 0x10, 0xB8, 0x92, 0x00, 0x10, 0xBC,
	0x92, 0x93, 0xA2, 0xE4, 0x92, 0x00, 0x10, 0xC0, 0x92, 0x93, 0xA2, 0xD4, 0x92, 0x00, 0x10, 0xC4,
	0x92, 0x93, 0xA2, 0xC4, 0x92, 0x00, 0x10, 0xC8, 0x92, 0x93, 0xA2, 0xB4, 0x92, 0x00, 0x10, 0xCC,
	0x92, 0x93, 0xC0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD0
};

static HRESULT(__cdecl *ExecuteSupervisorChallenge)(DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer); // set when XamLoaderExecuteAsyncChallenge is called

DWORD CreateXKEBuffer(PBYTE pBuffer, DWORD dwSize, PBYTE pbSalt);
DWORD XamLoaderExecuteAsyncChallenge(DWORD dwAddress, DWORD dwTaskParam1, PBYTE pbDaeTableName, DWORD szDaeTableName, PBYTE pbBuffer, DWORD cbBuffer);