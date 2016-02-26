#include "stdafx.h"

BYTE sessionKey[0x10];
SERVER_GET_TIME_RESPONSE userTime;
SERVER_UPDATE_PRESENCE_REQUEST presenceRequest;
SERVER_UPDATE_PRESENCE_RESPONSE presenceResponse;

extern KEY_VAULT_DATA keyVault;
extern WCHAR wNotifyMsg[100];
extern BOOL hasChallenged;
extern BOOL isDevkit;
extern BOOL isAuthed;

HRESULT initNetwork()
{
	if (StartupServerCommunicator() != S_OK)
	{
		setNotifyMsg(L"XeOnline - eNet Error");
		return E_FAIL;
	}
	else if (ServerGetSalt() != S_OK)
	{
		setNotifyMsg(L"XeOnline - eCon Error");
		return E_FAIL;
	}
	else if (ServerGetStatus() != S_OK)
	{
		setNotifyMsg(L"XeOnline - eStat Error");
		return E_FAIL;
	}

	isAuthed = TRUE;
	return S_OK;
}

HRESULT HandleUpdate()
{
	DWORD moduleSize = 0;
	if (ReceiveData(&moduleSize, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return E_FAIL;
	}

	BYTE* moduleBuffer = (BYTE*)XPhysicalAlloc(moduleSize, MAXULONG_PTR, NULL, PAGE_READWRITE);
	if (moduleBuffer == NULL) return E_FAIL;

	if (ReceiveData(moduleBuffer, moduleSize) == ERROR_SUCCESS)
	{
		//if (!CWriteFile(FILE_CLIENT_PATH, moduleBuffer, moduleSize))
		//{
		//	XPhysicalFree(moduleBuffer);
		//	return E_FAIL;
		//}
	}

	XPhysicalFree(moduleBuffer);
	return ERROR_SUCCESS;
}

HRESULT ServerGetSalt()
{
	SERVER_GET_SALT_REQUEST* request = (SERVER_GET_SALT_REQUEST*)XPhysicalAlloc(sizeof(SERVER_GET_SALT_REQUEST), MAXULONG_PTR, NULL, PAGE_READWRITE);
	SERVER_GET_SALT_RESPONSE response;

	if (!request) return E_FAIL;

	request->Version = XSTL_CLIENT_VERSION;
	memcpy(request->CpuKey, getCpuKey(), 0x10);
	memcpy(request->KeyVault, &keyVault.Data, 0x4000);

	if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_SALT, request, sizeof(SERVER_GET_SALT_REQUEST), &response, sizeof(SERVER_GET_SALT_RESPONSE), TRUE) != ERROR_SUCCESS)
	{
		XPhysicalFree(request);
		EndCommand();
		return E_FAIL;
	}

	XPhysicalFree(request);
	HRESULT ret = E_FAIL;

	switch (response.Status)
	{
	case XSTL_STATUS_SUCCESS:
	{
		ret = ReceiveData(sessionKey, 16);
		EndCommand();
		return ret;
	}
	case XSTL_STATUS_UPDATE:
	{
		ret = HandleUpdate();
		EndCommand();

		if (ret == ERROR_SUCCESS)
			HalReturnToFirmware(HalFatalErrorRebootRoutine);

		return ret;
	}
	case XSTL_STATUS_EXPIRED:
	{
		EndCommand();
		setNotifyMsg(L"XeOnline - Time Expired");
		return ret;
	}
	default:
	{
		EndCommand();
		setNotifyMsg(L"XeOnline - Unknown User");
		return ret;
	}
	}

	return E_FAIL;
}

HRESULT ServerGetStatus()
{
	SERVER_GET_STATUS_REQUEST statusRequest;
	SERVER_GET_STATUS_RESPONSE statusResponse;

	//MemoryBuffer mbXBLS;
	//if (!FileExists(FILE_CLIENT_PATH))
	//{
	//	return E_FAIL;
	//}

	//if (CReadFile(FILE_CLIENT_PATH, mbXBLS) != TRUE)
	//{
	//	return E_FAIL;
	//}
	//HANDLE loaderHandle = GetModuleHandle("Crypt.xex");
	//PVOID pSectionData;
	//DWORD pSectionSize;

	//DebugBreak();

	//if (!XGetModuleSection(GetModuleHandle("Crypt.xex"), "hud", &pSectionData, &pSectionSize))
	//	return E_FAIL;

	//XeCryptHmacSha(sessionKey, 16, (PBYTE)(PVOID)pSectionData, pSectionSize - 0x10, NULL, 0, NULL, 0, statusRequest.ExecutableHash, 20);

	memcpy(statusRequest.CpuKey, getCpuKey(), 0x10);

	if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_STATUS, &statusRequest, sizeof(SERVER_GET_STATUS_REQUEST), &statusResponse, sizeof(SERVER_GET_STATUS_RESPONSE)) != ERROR_SUCCESS)
		return E_FAIL;

	if (statusResponse.Status != XSTL_STATUS_SUCCESS)
		return E_FAIL;

	return S_OK;
}

HRESULT ServerGetTime()
{
	ZeroMemory(&userTime, sizeof(SERVER_GET_TIME_RESPONSE));

	if (!isAuthed)
		return S_OK;

	SERVER_GET_TIME_REQUEST timeRequest;
	memcpy(timeRequest.CpuKey, getCpuKey(), 0x10);

	if (SendCommand(XSTL_SERVER_COMMAND_ID_GET_TIME, &timeRequest, sizeof(SERVER_GET_TIME_REQUEST), &userTime, sizeof(SERVER_GET_TIME_RESPONSE)) != ERROR_SUCCESS)
		return E_FAIL;

	if (userTime.Status != XSTL_STATUS_SUCCESS)
		return E_FAIL;

	return S_OK;
}

HRESULT updateUserTime()
{
	userTime.userDays = 500;
	return S_OK;

	// remove this l8r
	if (ServerGetTime() != S_OK)
	{
		swprintf(wNotifyMsg, sizeof(wNotifyMsg) / sizeof(WCHAR), L"User not found.");
		return E_FAIL;
	}

	swprintf(wNotifyMsg, sizeof(wNotifyMsg) / sizeof(WCHAR), userTime.userDays > 365 ? L"XeOnline Lifetime" : L"Time Remaining: %iD %iH %iM", userTime.userDays, userTime.userTimeRemaining / 3600, (userTime.userTimeRemaining % 3600) / 60);
	return S_OK;
}

VOID ServerUpdatePresenceThread()
{
	//for (int i = 0; i < 10; i++)
	//{
	//	if (initNetwork() == S_OK)
	//		break;
	//	else if (isNotifyMsgSet())
	//		break;

	//	Sleep(1000);
	//}

	//Sleep(10 * 1000);

	if (isNotifyMsgSet())
	{
		XNotifyUI(wNotifyMsg);
		return;
	}

	isAuthed = TRUE;


	if (!isAuthed)
	{
		XNotifyUI(L"XeOnline Disabled");
		return;
	}

	XNotifyUI(L"XeOnline Enabled");
	setLiveBlock(FALSE);
	return;

	while (!hasChallenged)
		Sleep(0);

	while (TRUE)
	{
		updateUserTime();

		//XeCryptHmacShaInit()
		memcpy(presenceRequest.SessionKey, sessionKey, 16);
		presenceRequest.Version = XSTL_CLIENT_VERSION;

		if (SendCommand(XSTL_SERVER_COMMAND_ID_UPDATE_PRESENCE, &presenceRequest, sizeof(SERVER_UPDATE_PRESENCE_REQUEST), &presenceResponse, sizeof(SERVER_UPDATE_PRESENCE_RESPONSE)) != ERROR_SUCCESS)
			doErrShutdown(L"XeOnline - PSR Error", TRUE);

		switch (presenceResponse.Status)
		{
		case XSTL_STATUS_SUCCESS:
		{
			break;
		}
		case XSTL_STATUS_UPDATE:
		{
			XNotifyUI(L"XeOnline - Update Available");
			break;
		}
		case XSTL_STATUS_EXPIRED:
		{
			doErrShutdown(L"XeOnline - Time Expired", TRUE);
			break;
		}
		default:
		{
			doErrShutdown(L"XeOnline - Fatal Error", TRUE);
			break;
		}
		}

		Sleep(10 * 60000);
	}

	VdDisplayFatalError(69);
}