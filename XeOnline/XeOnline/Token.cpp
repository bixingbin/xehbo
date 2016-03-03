#include "stdafx.h"

extern SERVER_GET_TIME_RESPONSE userTime;

WCHAR wToken[20];
WCHAR wTokenMsg[50];
BOOL bRedeem = FALSE;
XOVERLAPPED pOverlapped;

VOID redeemTokenInit()
{
	XShowKeyboardUI(XamHudGetUserIndex(), VKBD_LATIN_SUBSCRIPTION, NULL, NULL, L"Please enter a code below.", wToken, (sizeof(wToken) / sizeof(WCHAR)) + 1, &pOverlapped);

	while (!XHasOverlappedIoCompleted(&pOverlapped))
		Sleep(0);

	if (XGetOverlappedResult(&pOverlapped, NULL, TRUE) == ERROR_SUCCESS)
	{
		if(wcslen(wToken) != sizeof(wToken) / sizeof(WCHAR))
			return;

		SERVER_CODE_REDEEM_REQUEST codeReq;
		SERVER_CODE_REDEEM_RESPONSE codeResp;
		memcpy(codeReq.CpuKey, getCpuKey(), 0x10);
		memcpy(codeReq.tokenCode, wToken, sizeof(wToken));
		codeReq.redeem = bRedeem;

		if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_TOKEN, &codeReq, sizeof(SERVER_CODE_REDEEM_REQUEST), &codeResp, sizeof(SERVER_CODE_REDEEM_RESPONSE)) != ERROR_SUCCESS)
		{
			XNotifyUI(L"XeOnline - Error validating token!");
			return;
		}

		if (codeResp.Status != XSTL_STATUS_SUCCESS || codeResp.userDays <= 0)
		{
			XNotifyUI(L"XeOnline - Invalid token!");
			return;
		}

		if (bRedeem) swprintf(wTokenMsg, sizeof(wTokenMsg) / sizeof(WCHAR), codeResp.userDays == 1 ? L"XeOnline - %i day added" : L"XeOnline - %i days added", codeResp.userDays);
		else swprintf(wTokenMsg, sizeof(wTokenMsg) / sizeof(WCHAR), L"XeOnline - Valid %i day token", codeResp.userDays);
		XNotifyUI(wTokenMsg);
		
		if (bRedeem && !userTime.userDays && !userTime.userTimeRemaining)
			doErrShutdown(L"XeOnline - Rebooting to activate!", TRUE);
	}
}

VOID s_OnMessageBoxReturn(DWORD dwButtonPressed, XHUDOPENSTATE* hudOpenState)
{
	if (dwButtonPressed == 0 || dwButtonPressed == 1)
	{
		bRedeem = dwButtonPressed == 0;
		launchSysThread((LPTHREAD_START_ROUTINE)redeemTokenInit);
	}
	
	//// dump cache
	//PBYTE consoleHv = (PBYTE)XPhysicalAlloc(0x1000, MAXULONG_PTR, NULL, PAGE_READWRITE);
	//memset(consoleHv, 0xAA, 0x1000);
	//HvxPeekBytes(0x800002000001F810, consoleHv, 0x2);
	//HvxPeekBytes(0x8000020000010002, consoleHv + 0x4, 0x3FE);
	//HvxPeekBytes(0x800002000001040E, consoleHv + 0x404, 0x176);
	//HvxPeekBytes(0x80000200000105B6, consoleHv + 0x57C, 0x24A);
	//HvxPeekBytes(0x8000020000010800, consoleHv + 0x7C8, 0x400);
	//HvxPeekBytes(0x8000020000010C00, consoleHv + 0xBCA, 0x400);
	//CWriteFile("XeOnline:\\CACHE_SECOND_HASH.bin", consoleHv, 0x1000);
	//XPhysicalFree(consoleHv);

	//// create temp buffer for resp
	//PBYTE tempBuff = (PBYTE)XPhysicalAlloc(0x1000, MAXULONG_PTR, NULL, PAGE_READWRITE);

	//// salt from NiNJA
	//BYTE tempSaltb[0x10] = { 0x09, 0xCF, 0xC4, 0x6D, 0x4F, 0x0E, 0x0D, 0xED, 0x3C, 0x17, 0x91, 0x7C, 0xF4, 0x81, 0x4B, 0x27 };
	//PBYTE tempSalt = (PBYTE)XPhysicalAlloc(0x100, MAXULONG_PTR, 0x80, MEM_LARGE_PAGES | PAGE_READWRITE);
	//memcpy(tempSalt, tempSaltb, 0x10);

	//// write cache salt
	//BYTE cacheSalt[] = { 0xE4, 0xA7 };
	//HvxPokeBytes(0x800002000001F810, cacheSalt, 0x2);

	//// create resp offline
	//CreateXKEBuffer(tempBuff, 0x1000, tempSalt);

	//// free the data we created
	//XPhysicalFree(tempSalt);
	//XPhysicalFree(tempBuff);
}

VOID redeemToken()
{
	LPCWSTR pwszButtons[3] = { L"Redeem Code", L"Check Code", L"Cancel" };
	XamShowMessageBox(XamHudGetUserIndex(), L"XeOnline Menu", L"Please choose an option below.", ARRAYSIZE(pwszButtons), pwszButtons, 0, (MBOXRESULT)s_OnMessageBoxReturn, XMB_ALERTICON);
}