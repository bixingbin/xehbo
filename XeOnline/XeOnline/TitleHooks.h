#pragma once

#include "stdafx.h"

VOID InitializeTitleSpecificHooks(PLDR_DATA_TABLE_ENTRY ModuleHandle);

typedef enum _XBOX_GAMES : DWORD
{
	SYS_DASHBOARD = 0xFFFE07D1,
	SYS_XSHELL = 0xFFFE07FF,
	COD_BLACK_OPS_2 = 0x415608C3,
	COD_GHOSTS = 0x415608FC,
	COD_AW = 0x41560914
} XBOX_GAMES;

typedef struct _COD_CHAL_RESP{
	BYTE	bOnlineIPAddress[4];
QWORD	qwMachineId;
BYTE	bMacAddress[6];
BYTE	padding1[2];
float	fltUnknown1; //Geo1?
float	fltUnknown2; //Geo2?
WORD	wUnknown1;
BYTE	bSecurityFlag;
char	cConsoleSerialNumber[12];
BYTE	padding2[1];
char	cConsoleId[12];
WORD	wKernelVersion;
} COD_CHAL_RESP, *PCOD_CHAL_RESP;