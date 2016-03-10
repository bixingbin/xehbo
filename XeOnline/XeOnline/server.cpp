#include "stdafx.h"

SOCKET hSocket = INVALID_SOCKET;
BYTE rc4Key[0x10];
BYTE sessionKey[0x10];
SERVER_GET_TIME_RESPONSE userTime;

namespace server {
	HRESULT initCommand()
	{
		// Startup WSA
		WSADATA wsaData;
		if (NetDll_WSAStartupEx(XNCALLER_SYSAPP, MAKEWORD(2, 2), &wsaData, 0x2043C500) != 0)
			return E_FAIL;

		// Create TCP/IP socket
		if ((hSocket = NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			return E_FAIL;

		// disable socket encryption
		BOOL bSockOpt = TRUE;
		if (NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_MARKINSECURE, (PCSTR)&bSockOpt, sizeof(BOOL)) != 0)
			return E_FAIL;

		// set socket timeout
		DWORD timeout = 5000;
		if (NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_RCVTIMEO, (PCSTR)&timeout, sizeof(DWORD)) != 0) return E_FAIL;
		if (NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_SNDTIMEO, (PCSTR)&timeout, sizeof(DWORD)) != 0) return E_FAIL;

		// set send and receive buffer size
		DWORD sendRecvSize = SEND_RECV_SIZE;
		if (NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_RCVBUF, (PCSTR)&sendRecvSize, sizeof(DWORD)) != 0) return E_FAIL;
		if (NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_SNDBUF, (PCSTR)&sendRecvSize, sizeof(DWORD)) != 0) return E_FAIL;

		//WSAEVENT hEvent = WSACreateEvent();
		//XNDNS* pxndns = NULL;
		//NetDll_XNetDnsLookup(XNCALLER_SYSAPP, "xedev.cloudapp.net", hEvent, &pxndns);
		//WaitForSingleObject(hEvent, INFINITE);
		//xbox::utilities::log("pointer = %X, status = %X\n", pxndns, pxndns->iStatus);
		//memcpy(&httpServerAdd.sin_addr.S_un.S_un_b, &pxndns->aina[0], 4);
		//NetDll_XNetDnsRelease(XNCALLER_SYSAPP, pxndns);

		// set ip address
		sockaddr_in sAddrInfo;
		sAddrInfo.sin_family = AF_INET;
		sAddrInfo.sin_port = htons(51726);
		sAddrInfo.sin_addr.S_un.S_un_b.s_b1 = 40;
		sAddrInfo.sin_addr.S_un.S_un_b.s_b2 = 121;
		sAddrInfo.sin_addr.S_un.S_un_b.s_b3 = 83;
		sAddrInfo.sin_addr.S_un.S_un_b.s_b4 = 145;

		// connect to server
		if (NetDll_connect(XNCALLER_SYSAPP, hSocket, (sockaddr*)&sAddrInfo, sizeof(sAddrInfo)) == SOCKET_ERROR)
			return E_FAIL;

		return S_OK;
	}

	VOID endCommand()
	{
		if (hSocket != INVALID_SOCKET)
		{
			NetDll_shutdown(XNCALLER_SYSAPP, hSocket, SD_BOTH);
			NetDll_closesocket(XNCALLER_SYSAPP, hSocket);
			hSocket = INVALID_SOCKET;
		}
	}

	HRESULT receiveData(VOID* Buffer, DWORD BytesExpected)
	{
		// Make sure we are connected
		if (hSocket == INVALID_SOCKET) return E_FAIL;

		// Loop and recieve our data
		DWORD bytesLeft = BytesExpected;
		DWORD bytesRecieved = 0;
		while (bytesLeft > 0)
		{
			DWORD cbRecv = NetDll_recv(XNCALLER_SYSAPP, hSocket, (CHAR*)Buffer + bytesRecieved, bytesLeft, NULL);

			if (cbRecv == SOCKET_ERROR)
				return E_FAIL;

			if (cbRecv == 0)
				break;

			bytesLeft -= cbRecv;
			bytesRecieved += cbRecv;
		}

		// Decrypt our data now
		if (bytesRecieved != BytesExpected) return E_FAIL;
		XeCryptRc4(rc4Key, 0x10, (BYTE*)Buffer, bytesRecieved);
		return S_OK;
	}

	HRESULT sendData(DWORD CommandId, VOID* CommandData, DWORD DataLen)
	{
		// Make sure we are connected
		if (hSocket == INVALID_SOCKET) return E_FAIL;

		// alloc a temp buffer
		PBYTE tmpBuffer = (PBYTE)malloc(DataLen + 8);

		// Copy our id and len
		memcpy(tmpBuffer, &CommandId, sizeof(DWORD));
		memcpy(tmpBuffer + 4, &DataLen, sizeof(DWORD));

		// Encrypt and copy
		XeCryptRc4(rc4Key, 0x10, (BYTE*)CommandData, DataLen);
		memcpy(tmpBuffer + 8, CommandData, DataLen);

		// Send all our data
		DWORD bytesLeft = DataLen + 8;
		CHAR* curPos = (CHAR*)tmpBuffer;
		while (bytesLeft > 0)
		{
			DWORD sendSize = min(SEND_RECV_SIZE, bytesLeft);
			DWORD cbSent = NetDll_send(XNCALLER_SYSAPP, hSocket, curPos, sendSize, NULL);

			if (cbSent == SOCKET_ERROR)
			{
				free(tmpBuffer);
				return E_FAIL;
			}

			bytesLeft -= cbSent;
			curPos += cbSent;
		}

		// All done
		free(tmpBuffer);
		return S_OK;
	}

	HRESULT sendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Response, DWORD ResponseLength, BOOL KeepOpen = FALSE, BOOL NoReceive = FALSE)
	{
		// try to connect to server
		for (int i = 0; i < 10; i++)
		{
			endCommand();
			if (initCommand() == S_OK) break;
			else if (i == 9) return E_FAIL;
			Sleep(1000);
		}

		// try to send data, if it doesnt send then fail
		for (int i = 0; i < 10; i++)
		{
			if (sendData(CommandId, CommandData, CommandLength) == S_OK) break;
			else if (i == 9) return E_FAIL;
			Sleep(1000);
		}

		if (!NoReceive)
		{
			// Now lets get our response
			if (receiveData(Response, ResponseLength) != S_OK)
				return E_FAIL;
		}

		if (!KeepOpen)
			endCommand();

		return S_OK;
	}

	namespace main {
		HRESULT handleUpdate()
		{
			DWORD moduleSize = 0;
			if (receiveData(&moduleSize, sizeof(DWORD)) != ERROR_SUCCESS)
			{
				return E_FAIL;
			}

			BYTE* moduleBuffer = (BYTE*)XPhysicalAlloc(moduleSize, MAXULONG_PTR, NULL, PAGE_READWRITE);
			if (moduleBuffer == NULL) return E_FAIL;

			if (receiveData(moduleBuffer, moduleSize) == ERROR_SUCCESS)
			{
				//if (!writeFile(FILE_CLIENT_PATH, moduleBuffer, moduleSize))
				//{
				//	XPhysicalFree(moduleBuffer);
				//	return E_FAIL;
				//}
			}

			XPhysicalFree(moduleBuffer);
			return ERROR_SUCCESS;
		}

		HRESULT getSalt()
		{
			SERVER_GET_SALT_REQUEST* request = (SERVER_GET_SALT_REQUEST*)XPhysicalAlloc(sizeof(SERVER_GET_SALT_REQUEST), MAXULONG_PTR, NULL, PAGE_READWRITE);
			SERVER_GET_SALT_RESPONSE response;

			if (!request) return E_FAIL;

			request->Version = XSTL_CLIENT_VERSION;
			memcpy(request->CpuKey, xbox::hypervisor::getCpuKey(), 0x10);
			memcpy(request->KeyVault, &xbox::keyvault::data::buffer, 0x4000);

			if (sendCommand(XSTL_SERVER_COMMAND_ID_GET_SALT, request, sizeof(SERVER_GET_SALT_REQUEST), &response, sizeof(SERVER_GET_SALT_RESPONSE), TRUE) != ERROR_SUCCESS)
			{
				XPhysicalFree(request);
				endCommand();
				return E_FAIL;
			}

			XPhysicalFree(request);
			HRESULT ret = E_FAIL;

			switch (response.Status)
			{
			case XSTL_STATUS_SUCCESS:
			{
				ret = receiveData(sessionKey, 16);
				endCommand();
				return ret;
			}
			case XSTL_STATUS_UPDATE:
			{
				ret = handleUpdate();
				endCommand();

				if (ret == ERROR_SUCCESS)
					HalReturnToFirmware(HalFatalErrorRebootRoutine);

				return ret;
			}
			case XSTL_STATUS_EXPIRED:
			{
				endCommand();
				xbox::utilities::setNotifyMsg(L"XeOnline - Time Expired");
				return ret;
			}
			default:
			{
				endCommand();
				xbox::utilities::setNotifyMsg(L"XeOnline - Unknown User");
				return ret;
			}
			}

			return E_FAIL;
		}

		HRESULT getStatus()
		{
			SERVER_GET_STATUS_REQUEST statusRequest;
			SERVER_GET_STATUS_RESPONSE statusResponse;

			//MemoryBuffer mbXBLS;
			//if (!FileExists(FILE_CLIENT_PATH))
			//{
			//	return E_FAIL;
			//}

			//if (readFile(FILE_CLIENT_PATH, mbXBLS) != TRUE)
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

			memcpy(statusRequest.CpuKey, xbox::hypervisor::getCpuKey(), 0x10);

			if (sendCommand(XSTL_SERVER_COMMAND_ID_GET_STATUS, &statusRequest, sizeof(SERVER_GET_STATUS_REQUEST), &statusResponse, sizeof(SERVER_GET_STATUS_RESPONSE)) != ERROR_SUCCESS)
				return E_FAIL;

			if (statusResponse.Status != XSTL_STATUS_SUCCESS)
				return E_FAIL;

			return S_OK;
		}

		HRESULT getTime()
		{
			ZeroMemory(&userTime, sizeof(SERVER_GET_TIME_RESPONSE));

			if (!global::isAuthed)
				return S_OK;

			SERVER_GET_TIME_REQUEST timeRequest;
			memcpy(timeRequest.CpuKey, xbox::hypervisor::getCpuKey(), 0x10);

			if (sendCommand(XSTL_SERVER_COMMAND_ID_GET_TIME, &timeRequest, sizeof(SERVER_GET_TIME_REQUEST), &userTime, sizeof(SERVER_GET_TIME_RESPONSE)) != ERROR_SUCCESS)
				return E_FAIL;

			if (userTime.Status != XSTL_STATUS_SUCCESS)
				return E_FAIL;

			return S_OK;
		}

		HRESULT updateUserTime()
		{
			if (getTime() != S_OK)
			{
				swprintf(global::wNotifyMsg, sizeof(global::wNotifyMsg) / sizeof(WCHAR), L"User not found.");
				return E_FAIL;
			}

			swprintf(global::wNotifyMsg, sizeof(global::wNotifyMsg) / sizeof(WCHAR), userTime.userDays > 365 ? L"XeOnline Lifetime" : L"Time Remaining: %iD %iH %iM", userTime.userDays, userTime.userTimeRemaining / 3600, (userTime.userTimeRemaining % 3600) / 60);
			return S_OK;
		}

		HRESULT initNetwork()
		{
			XNADDR titleAddr;
			for (int i = 0; i < 30; i++)
			{
				XNetGetTitleXnAddr(&titleAddr);

				if (titleAddr.ina.S_un.S_addr != 0)
					break;

				Sleep(1000);
			}

			XeCryptSha((PBYTE)"XeOnline", 8, NULL, NULL, NULL, NULL, rc4Key, 0x10); // need to figure out dynamic key

			if (titleAddr.ina.S_un.S_addr == 0)
			{
				xbox::utilities::setNotifyMsg(L"XeOnline - eNet Error");
				return E_FAIL;
			}
			else if (getSalt() != S_OK)
			{
				xbox::utilities::setNotifyMsg(L"XeOnline - eCon Error");
				return E_FAIL;
			}
			else if (getStatus() != S_OK)
			{
				xbox::utilities::setNotifyMsg(L"XeOnline - eStat Error");
				return E_FAIL;
			}

			global::isAuthed = TRUE;
			return S_OK;
		}

		VOID presenceThread()
		{
			for (int i = 0; i < 10; i++)
			{
				if (initNetwork() == S_OK)
					break;
				else if (xbox::utilities::isNotifyMsgSet())
					break;

				Sleep(1000);
			}

			Sleep(10 * 1000);

			if (xbox::utilities::isNotifyMsgSet())
			{
				xbox::utilities::notify(global::wNotifyMsg);
				return;
			}

			if (!global::isAuthed)
			{
				xbox::utilities::notify(L"XeOnline Disabled");
				return;
			}

			xbox::utilities::notify(L"XeOnline Enabled");
			xbox::utilities::setLiveBlock(FALSE);
			return;

			while (!global::challenge::hasChallenged)
				Sleep(0);

			while (TRUE)
			{
				updateUserTime();

				SERVER_UPDATE_PRESENCE_REQUEST presenceRequest;
				SERVER_UPDATE_PRESENCE_RESPONSE presenceResponse;
				//XeCryptHmacShaInit()
				memcpy(presenceRequest.SessionKey, sessionKey, 16);
				presenceRequest.Version = XSTL_CLIENT_VERSION;

				if (sendCommand(XSTL_SERVER_COMMAND_ID_UPDATE_PRESENCE, &presenceRequest, sizeof(SERVER_UPDATE_PRESENCE_REQUEST), &presenceResponse, sizeof(SERVER_UPDATE_PRESENCE_RESPONSE)) != ERROR_SUCCESS)
					xbox::utilities::doErrShutdown(L"XeOnline - PSR Error", TRUE);

				switch (presenceResponse.Status)
				{
				case XSTL_STATUS_SUCCESS:
				{
					break;
				}
				case XSTL_STATUS_UPDATE:
				{
					xbox::utilities::notify(L"XeOnline - Update Available");
					break;
				}
				case XSTL_STATUS_EXPIRED:
				{
					xbox::utilities::doErrShutdown(L"XeOnline - Time Expired", TRUE);
					break;
				}
				default:
				{
					xbox::utilities::doErrShutdown(L"XeOnline - Fatal Error", TRUE);
					break;
				}
				}

				Sleep(10 * 60000);
			}

			VdDisplayFatalError(69);
		}

		VOID initialize()
		{
			xbox::utilities::createThread(presenceThread, TRUE, 2);
		}
	}

	namespace token {
		WCHAR wToken[20];
		WCHAR wTokenMsg[50];
		BOOL bRedeem = FALSE;
		XOVERLAPPED pOverlapped;

		VOID redeemTokenThread()
		{
			XShowKeyboardUI(XamHudGetUserIndex(), VKBD_LATIN_SUBSCRIPTION, NULL, NULL, L"Please enter a code below.", wToken, (sizeof(wToken) / sizeof(WCHAR)) + 1, &pOverlapped);

			while (!XHasOverlappedIoCompleted(&pOverlapped))
				Sleep(0);

			if (XGetOverlappedResult(&pOverlapped, NULL, TRUE) == ERROR_SUCCESS)
			{
				if (wcslen(wToken) != sizeof(wToken) / sizeof(WCHAR))
					return;

				SERVER_CODE_REDEEM_REQUEST tokenRequest;
				SERVER_CODE_REDEEM_RESPONSE tokenResponse;
				memcpy(tokenRequest.CpuKey, xbox::hypervisor::getCpuKey(), 0x10);
				memcpy(tokenRequest.tokenCode, wToken, sizeof(wToken));
				tokenRequest.redeem = bRedeem;

				if (sendCommand(XSTL_SERVER_COMMAND_ID_GET_TOKEN, &tokenRequest, sizeof(SERVER_CODE_REDEEM_REQUEST), &tokenResponse, sizeof(SERVER_CODE_REDEEM_RESPONSE)) != ERROR_SUCCESS)
				{
					xbox::utilities::notify(L"XeOnline - Error validating token!");
					return;
				}

				if (tokenResponse.Status != XSTL_STATUS_SUCCESS || tokenResponse.userDays <= 0)
				{
					xbox::utilities::notify(L"XeOnline - Invalid token!");
					return;
				}

				if (bRedeem) swprintf(wTokenMsg, sizeof(wTokenMsg) / sizeof(WCHAR), tokenResponse.userDays == 1 ? L"XeOnline - %i day added" : L"XeOnline - %i days added", tokenResponse.userDays);
				else swprintf(wTokenMsg, sizeof(wTokenMsg) / sizeof(WCHAR), L"XeOnline - Valid %i day token", tokenResponse.userDays);
				xbox::utilities::notify(wTokenMsg);

				if (bRedeem && !userTime.userDays && !userTime.userTimeRemaining)
					xbox::utilities::doErrShutdown(L"XeOnline - Rebooting to activate!", TRUE);
			}
		}

		VOID s_OnMessageBoxReturn(DWORD dwButtonPressed, XHUDOPENSTATE* hudOpenState)
		{
			if (dwButtonPressed == 0 || dwButtonPressed == 1)
			{
				bRedeem = dwButtonPressed == 0;
				xbox::utilities::createThread(redeemTokenThread);
			}
		}

		VOID initialize()
		{
			LPCWSTR pwszButtons[3] = { L"Redeem Code", L"Check Code", L"Cancel" };
			XamShowMessageBox(XamHudGetUserIndex(), L"XeOnline Menu", L"Please choose an option below.", ARRAYSIZE(pwszButtons), pwszButtons, 0, (MBOXRESULT)s_OnMessageBoxReturn, XMB_ALERTICON);
		}
	}
}