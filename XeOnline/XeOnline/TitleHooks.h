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