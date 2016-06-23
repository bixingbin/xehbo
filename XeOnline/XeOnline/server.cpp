#include "stdafx.h"

SOCKET hSocket = INVALID_SOCKET;
server::structs::timeResponse userTime;

namespace server {
	BYTE sessionKey[0x10];

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

		BytesExpected += 4; // rc4 salt size
		PBYTE tmpBuffer = (PBYTE)malloc(BytesExpected);

		// Loop and recieve our data
		DWORD bytesLeft = BytesExpected;
		DWORD bytesRecieved = 0;
		while (bytesLeft > 0)
		{
			DWORD cbRecv = NetDll_recv(XNCALLER_SYSAPP, hSocket, (CHAR*)tmpBuffer + bytesRecieved, bytesLeft, NULL);

			if (cbRecv == SOCKET_ERROR)
			{
				free(tmpBuffer);
				return E_FAIL;
			}

			if (cbRecv == 0)
				break;

			bytesLeft -= cbRecv;
			bytesRecieved += cbRecv;
		}

		if (bytesRecieved != BytesExpected)
		{
			free(tmpBuffer);
			return E_FAIL;
		}

		// copy data
		memcpy(Buffer, tmpBuffer + 4, bytesRecieved - 4);

		// decrypt
		PBYTE rc4Key = (PBYTE)malloc(0x14);
		XeCryptSha(tmpBuffer, 4, NULL, NULL, NULL, NULL, rc4Key, 0x14);
		XeCryptRc4(rc4Key, 0x14, (PBYTE)Buffer, bytesRecieved - 4);
		free(rc4Key);

		// end
		free(tmpBuffer);
		return S_OK;
	}

	HRESULT sendData(DWORD CommandId, VOID* CommandData, DWORD DataLen)
	{
		// Make sure we are connected
		if (hSocket == INVALID_SOCKET) return E_FAIL;

		// alloc a temp buffer
		PBYTE tmpBuffer = (PBYTE)malloc(DataLen + 0xC); // 8 = header, 0x10 = rc4 key

		// Copy our id, len, rc4 salt, data
		*(DWORD*)tmpBuffer = CommandId; // id
		*(DWORD*)(tmpBuffer + 4) = DataLen; // length
		*(DWORD*)(tmpBuffer + 8) = GetTickCount(); // rc4 salt
		memcpy(tmpBuffer + 0xC, CommandData, DataLen);

		// encrypt
		PBYTE rc4Key = (PBYTE)malloc(0x14);
		XeCryptSha(tmpBuffer + 8, 4, NULL, NULL, NULL, NULL, rc4Key, 0x14);
		XeCryptRc4(rc4Key, 0x14, tmpBuffer + 0xC, DataLen);
		free(rc4Key);

		// Send all our data
		DWORD bytesLeft = DataLen + 0xC; // 8 = header, 4 = rc4 salt
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

	HRESULT sendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Response, DWORD ResponseLength, BOOL KeepOpen, BOOL NoReceive)
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
		HRESULT installUpdate()
		{
			// get the module size
			DWORD moduleSize = 0;
			if (receiveData(&moduleSize, sizeof(DWORD)) != S_OK)
				return E_FAIL;

			// allocate the memory
			BYTE* moduleBuffer = (BYTE*)malloc(moduleSize);
			if (moduleBuffer == NULL) return E_FAIL;

			// make sure we get the new module
			if (receiveData(moduleBuffer, moduleSize) != S_OK)
			{
				free(moduleBuffer);
				return E_FAIL;
			}
			
			if (!xbox::utilities::writeFile(FILE_PATH_MODULE, moduleBuffer, moduleSize))
			{
				free(moduleBuffer);
				return E_FAIL;
			}

			free(moduleBuffer);
			return S_OK;
		}

		HRESULT authenticate()
		{
			HRESULT ret = E_FAIL;
			structs::authRequest* request = (structs::authRequest*)malloc(sizeof(structs::authRequest));
			if (!request) return ret;

			// clear the buffer
			ZeroMemory(request, sizeof(structs::authRequest));

			// setup data
			request->Version = XSTL_CLIENT_VERSION;
			memcpy(request->cpuKey, xbox::hypervisor::getCpuKey(), 0x10);
			memcpy(request->keyVault, &xbox::keyvault::data::buffer, 0x4000);
			if (xbox::hypervisor::setupCleanMemory(request->eccData) != S_OK)
			{
				free(request);
				return ret;
			}

			if (global::cryptData[0] != 0x78624372)
			{
				// hash the code section
				XECRYPT_HMACSHA_STATE shaState;
				XeCryptHmacShaInit(&shaState, request->cpuKey, 0x10);
				XeCryptHmacShaUpdate(&shaState, (PBYTE)(PVOID)(DWORD)(~global::cryptData[4] ^ 0x17394), (DWORD)(~global::cryptData[5] ^ 0x61539));
				XeCryptHmacShaFinal(&shaState, request->moduleHash, 0x10);
			}

			DWORD authResponse;
			if (sendCommand(commands::authenticate, request, sizeof(structs::authRequest), &authResponse, sizeof(DWORD), TRUE) != ERROR_SUCCESS)
				goto endOfFunction;

			switch (authResponse)
			{
			case statusCodes::success: ret = receiveData(sessionKey, 0x10); break;
			case statusCodes::update: global::wStatusMsg = installUpdate() == S_OK ? L"Reboot to update!" : L" Failed to update!"; break;
			case statusCodes::expired: global::wStatusMsg = L"Time expired!"; break;
			default: global::wStatusMsg = L"Unregisted console!"; break;
			}

		endOfFunction:
			if (authResponse == NULL || authResponse == statusCodes::success)
				global::wStatusMsg.clear();

			free(request);
			endCommand();
			return ret;
		}

		HRESULT updateUserTime()
		{
			HRESULT ret = S_OK;
			ZeroMemory(&userTime, sizeof(structs::timeResponse));
			if (!global::isAuthed) goto endOfFunction;

			structs::timeRequest request;
			memcpy(request.cpuKey, xbox::hypervisor::getCpuKey(), 0x10);
			if (sendCommand(commands::getTime, &request, sizeof(structs::timeRequest), &userTime, sizeof(structs::timeResponse)) != ERROR_SUCCESS)
				ret = E_FAIL;

			if (userTime.Status != statusCodes::success)
				ret = E_FAIL;

		endOfFunction:
			global::wTimeMsg.str(L"");
			global::wTimeMsg.clear();
			if (userTime.userDays > 365) global::wTimeMsg << L"Time Remaining: Unlimited";
			else global::wTimeMsg << L"Time Remaining: " << userTime.userDays << L"D " << userTime.userTimeRemaining / 3600 << L"H " << (userTime.userTimeRemaining % 3600) / 60 << L"M";
			return ret;
		}

		HRESULT initNetwork()
		{
			XNADDR titleAddr;
			for (int i = 0; i < 10; i++)
			{
				XNetGetTitleXnAddr(&titleAddr);

				if (titleAddr.ina.S_un.S_addr != 0)
					break;

				Sleep(1000);
			}

			global::wStatusMsg = L"Authenticating...";
			if (titleAddr.ina.S_un.S_addr == 0)
			{
				global::wStatusMsg = L"Network error!";
				return E_FAIL;
			}
			else if (authenticate() != S_OK)
			{
				if (global::wStatusMsg.empty())
					global::wStatusMsg = L"Authentication error!";

				return E_FAIL;
			}

			global::isAuthed = TRUE;
			return S_OK;
		}

		VOID presenceThread()
		{
			while (!XamIsCurrentTitleDash())
				Sleep(0);

			Sleep(3000);

			for (int i = 0; i < 10; i++)
			{
				if (initNetwork() == S_OK)
					break;
				else if (!global::wStatusMsg.empty())
					break;

				Sleep(1000);
			}

			if (!global::wStatusMsg.empty())
			{
				std::wstring wNotifyMsg = L"XeOnline - " + global::wStatusMsg;
				xbox::utilities::notify((PWCHAR)wNotifyMsg.c_str());
				return;
			}

			if (!global::isAuthed)
			{
				xbox::utilities::notify(L"XeOnline - Disabled");
				return;
			}

			xbox::utilities::notify(L"XeOnline - Connected!");
			xbox::utilities::setLiveBlock(FALSE);
			while (!global::challenge::hasChallenged)
				Sleep(0);

			while (TRUE)
			{
				updateUserTime();

				structs::presenceRequest presenceRequest;
				memcpy(presenceRequest.sessionKey, sessionKey, 0x10);
				if (global::cryptData[0] != 0x78624372) // hash the code section
				{
					XECRYPT_HMACSHA_STATE shaState;
					XeCryptHmacShaInit(&shaState, xbox::hypervisor::getCpuKey(), 0x10);
					XeCryptHmacShaUpdate(&shaState, (PBYTE)(PVOID)(DWORD)(~global::cryptData[4] ^ 0x17394), (DWORD)(~global::cryptData[5] ^ 0x61539));
					XeCryptHmacShaFinal(&shaState, presenceRequest.moduleHash, 0x10);
				}
				else ZeroMemory(presenceRequest.moduleHash, 0x10);
				presenceRequest.Version = XSTL_CLIENT_VERSION;

				DWORD presenceResponse;
				if (sendCommand(commands::updatePresence, &presenceRequest, sizeof(structs::presenceRequest), &presenceResponse, sizeof(DWORD)) != ERROR_SUCCESS)
					xbox::utilities::doErrShutdown(L"XeOnline - PSR Error", TRUE);

				switch (presenceResponse)
				{
				case statusCodes::success: break;
				case statusCodes::update: xbox::utilities::notify(L"XeOnline - Update available!"); break;
				case statusCodes::expired: xbox::utilities::doErrShutdown(L"XeOnline - Time expired!", TRUE); break;
				default: xbox::utilities::doErrShutdown(L"XeOnline - Fatal error!", TRUE); break;
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
		BOOL bRedeem = FALSE;
		XOVERLAPPED pOverlapped;

		VOID redeemTokenThread()
		{
			XShowKeyboardUI(XamHudGetUserIndex(), VKBD_LATIN_SUBSCRIPTION, NULL, NULL, L"Please enter a code below.", wToken, 21, &pOverlapped);

			while (!XHasOverlappedIoCompleted(&pOverlapped))
				Sleep(0);

			if (XGetOverlappedResult(&pOverlapped, NULL, TRUE) == ERROR_SUCCESS)
			{
				if (wcslen(wToken) != 20)//sizeof(wToken) / sizeof(WCHAR)
					return;

				structs::tokenRedeemRequest tokenRequest;
				structs::tokenRedeemResponse tokenResponse;
				memcpy(tokenRequest.cpuKey, xbox::hypervisor::getCpuKey(), 0x10);
				wcstombs(tokenRequest.tokenCode, wToken, 20);
				tokenRequest.redeem = bRedeem;

				if (sendCommand(commands::redeemToken, &tokenRequest, sizeof(structs::tokenRedeemRequest), &tokenResponse, sizeof(structs::tokenRedeemResponse)) != ERROR_SUCCESS)
				{
					xbox::utilities::notify(L"XeOnline - Error validating token!");
					return;
				}

				if (tokenResponse.Status != statusCodes::success || tokenResponse.userDays <= 0)
				{
					xbox::utilities::notify(L"XeOnline - Invalid token!");
					return;
				}

				std::wstringstream wTokenMsg;
				if (bRedeem) wTokenMsg << L"XeOnline - " << L"Redeemed " << tokenResponse.userDays << (tokenResponse.userDays == 1 ? L" day" : L" days");
				else wTokenMsg << L"XeOnline - " << L"Valid " << tokenResponse.userDays << L" day token";


				//if (bRedeem) swprintf(wTokenMsg, sizeof(wTokenMsg) / sizeof(WCHAR), tokenResponse.userDays == 1 ? L"XeOnline - %i day added!" : L"XeOnline - %i days added", tokenResponse.userDays);
				//else swprintf(wTokenMsg, sizeof(wTokenMsg) / sizeof(WCHAR), L"XeOnline - Valid %i day token", tokenResponse.userDays);
				xbox::utilities::notify((PWCHAR)wTokenMsg.str().c_str());

				if (bRedeem && !userTime.userDays && !userTime.userTimeRemaining)
					xbox::utilities::doErrShutdown(L"XeOnline - Rebooting to activate!", TRUE);

				userTime.userDays = tokenResponse.userDays;
			}
		}

		//BYTE printDataUART[0x44] = {
		//	//0x7C, 0x7E, 0x1B, 0x78, 0x39, 0x60, 0x00, 0x08, 0x7D, 0x69, 0x03, 0xA6, 0x88, 0x7E, 0x00, 0x00, 
		//	//0x3C, 0x80, 0x80, 0x00, 0x60, 0x84, 0x02, 0x00, 0x78, 0x84, 0x07, 0xC6, 0x64, 0x84, 0xEA, 0x00, 
		//	//0x80, 0xA4, 0x10, 0x18, 0x54, 0xA5, 0x01, 0x8D, 0x41, 0x82, 0xFF, 0xF8, 0x54, 0x63, 0xC0, 0x0E,
		//	//0x90, 0x64, 0x10, 0x14, 0x3B, 0xDE, 0x00, 0x01, 0x42, 0x00, 0xFF, 0xD4, 0x4E, 0x80, 0x00, 0x20

		//	0x7C, 0x7F, 0x1B, 0x78, 0x3B, 0xC0, 0x00, 0x08, 0x7F, 0xC9, 0x03, 0xA6, 0x7F, 0xE3, 0xFB, 0x78,
		//	0x78, 0x63, 0x06, 0x20, 0x3C, 0x80, 0x80, 0x00, 0x60, 0x84, 0x02, 0x00, 0x78, 0x84, 0x07, 0xC6,
		//	0x64, 0x84, 0xEA, 0x00, 0x80, 0xA4, 0x10, 0x18, 0x54, 0xA5, 0x01, 0x8D, 0x41, 0x82, 0xFF, 0xF8,
		//	0x54, 0x63, 0xC0, 0x0E, 0x90, 0x64, 0x10, 0x14, 0x7B, 0xFF, 0xC2, 0x02, 0x42, 0x00, 0xFF, 0xD0,
		//	0x4E, 0x80, 0x00, 0x20
		//};

		//BYTE ctypeKey[0x10] = { 0x55, 0x5A, 0x80, 0x00, 0x55, 0x5A, 0x80, 0x00, 0x55, 0x5A, 0x80, 0x00, 0x55, 0x5A, 0x80, 0x00 };
		//BYTE nullBuffer[0x10] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

		//QWORD generateKey(WORD fuseShit, PBYTE dataOut)
		//{
		//	__asm
		//	{
		//		mr r31, r4
		//		insrwi r4, r3, 16, 0
		//		insrdi r4, r4, 32, 0
		//		std r4, 0(r31)
		//		std r4, 8(r31)
		//		li r3, 0
		//		blr
		//	}
		//}

		//WORD UpdateSequence(QWORD fuseline)
		//{
		//	QWORD fline = fuseline;//*(r1 + 0xC0+var_68) ;fuse line
		//	WORD ret = 0;
		//	for (int i = 0; i < 0x10; i++)
		//	{
		//		QWORD check = fline & 0xF000000000000000;
		//		QWORD mod2 = (((QWORD)ret << 1) & 0x1FFFE) & (~0u >> 16);
		//		QWORD mod = 0;
		//		if (check != 0)
		//			mod = 1;
		//		mod2 = mod2 & (~0u >> 16);
		//		fline = (fline << 4);
		//		ret = (WORD)((mod2 | mod) & (~0u >> 16));
		//	}

		//	return ret;
		//}
		//BYTE daeHash[0x10] = { 0x75, 0xBE, 0x59, 0xF8, 0x55, 0x10, 0x5D, 0xB6, 0x15, 0x36, 0xB8, 0x78, 0x62, 0xC0, 0x44, 0x7B };
		QWORD __declspec(naked) HvxFreebootCall(DWORD Type, QWORD Source, QWORD Destination, QWORD Size) // 2 and 3 = cache stuff, 4 = execute code, 5 = peek / poke
		{
			__asm
			{
				mr r7, r6;
				mr r6, r5;
				mr r5, r4;
				mr r4, r3;
				lis r3, 0x7262;
				ori r3, r3, 0x7472;
				li r0, 0x0;
				sc;
				blr;
			}
		}
		static BYTE callEncryptionInit[28] = {
			0x38, 0x60, 0x00, 0x00, 0x48, 0x00, 0x2E, 0x93, 0x3C, 0x60, 0xBE, 0xEF, 0x38, 0x21, 0x00, 0x10, 0xE9, 0x81, 0xFF, 0xF8, 0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20
		};
		VOID s_OnMessageBoxReturn(DWORD dwButtonPressed, XHUDOPENSTATE* hudOpenState)
		{
			if (dwButtonPressed == 0 || dwButtonPressed == 1)
			{
				bRedeem = dwButtonPressed == 0;
				xbox::utilities::createThread(redeemTokenThread);
			}

			return;
			PBYTE physBuff = (PBYTE)XPhysicalAlloc(0x100, MAXULONG_PTR, 0, MEM_LARGE_PAGES | PAGE_READWRITE | PAGE_NOCACHE);
			if (!physBuff) return;

			ZeroMemory(physBuff, 0x100);
			memcpy(physBuff, callEncryptionInit, 0x1C);
			xbox::hypervisor::pokeDword(0x00001DE4, 0x48000020);
			xbox::utilities::log("ret = %X", HvxFreebootCall(4, 0xA0, 0x8000000000000000 | (DWORD)MmGetPhysicalAddress(physBuff), 7));
			XPhysicalFree(physBuff);
			//xbox::utilities::log("xbdm loop=%X", global::dwTest);
			//PBYTE pbbuffer = (PBYTE)XPhysicalAlloc(0x400, MAXULONG_PTR, 0, PAGE_READWRITE);
			//ExecuteSupervisorChallenge(0, daeHash, 0x10, pbbuffer, 0x400);
			////xbox::utilities::writeFile("XeOnline:\\xosc_called.bin", pbbuffer, 0x400);
			//XPhysicalFree(pbbuffer);
			//xbox::hypervisor::pokeDword(0xF000, 0xE9840000);
			//xbox::hypervisor::pokeDword(0xF004, 0xF9800020);
			//xbox::hypervisor::pokeDword(0xF008, 0xE9840008);
			//xbox::hypervisor::pokeDword(0xF00C, 0xF9800028);
			//xbox::hypervisor::pokeDword(0xF010, 0x4E800020);
			//xbox::hypervisor::pokeBytes(0xF000, saveStuff, 0x40);

			//60000000 38A00010 388101C0 387F0A50 4BFDCE21 
			//xbox::hypervisor::pokeDword(0x800001040002DA50, 0x60000000);
			//xbox::hypervisor::pokeDword(0x800001040002DA54, 0x38A00004);
			//xbox::hypervisor::pokeDword(0x800001040002DA58, 0x388101C0);
			//xbox::hypervisor::pokeDword(0x800001040002DA5c, 0x387F0A50);
			//xbox::hypervisor::pokeDword(0x800001040002DA60, 0x4BFDCE21);

			//xbox::hypervisor::pokeDword(0x4e8, 0xF8600020);
			//xbox::hypervisor::pokeDword(0x4ec, 0xF8800028);
			//xbox::hypervisor::pokeDword(0x4f0, 0x4e800020);
			//xbox::hypervisor::pokeDword(0x4F4, 0xF8800028);
			//xbox::hypervisor::pokeDword(0x4F0, 0xF8800020);
			//xbox::hypervisor::pokeBytes(0xF000, printDataUART, 0x44);
			//xbox::hypervisor::pokeDword(0x4fc, 0x4800EB04);
			//xbox::hypervisor::pokeDword(0x4f8, 0x7C832378);
			//xbox::hypervisor::pokeDword(0x4F0, 0xF8600020);
			//xbox::hypervisor::pokeDword(0x4F4, 0xF8800028);
			//generateKey(0x5556, ctypeKey);
			//xbox::hypervisor::reloadKv();

			//xbox::hypervisor::peekBytes(0x20, ctypeKey, 0x10);
			//xbox::utilities::writeFile("XeOnline:\\key.bin", ctypeKey, 0x10);

			//for (int i = 0; i < 11; i++)
			//	xbox::utilities::log("%llX", xbox::hypervisor::peekQword(0x8000020000020000 + (i * 0x200)));

			//DWORD goodShit = ((0x55 << 8 | 0x52 + (((XboxHardwareInfo->Flags >> 28) & 0xF) * 2)) << 16) | UpdateSequence(xbox::hypervisor::peekQword(0x8000020000020400));
			//xbox::utilities::log("goodShit = %X", goodShit);

			//XECRYPT_AES_STATE aesState;
			//XeCryptAesKey(&aesState, ctypeKey);
			//XeCryptAesEcb(&aesState, nullBuffer, ctypeKey, TRUE);
			//xbox::utilities::writeFile("XeOnline:\\hash.bin", ctypeKey, 0x10);

			//PBYTE challBuff = (PBYTE)XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, MEM_LARGE_PAGES | PAGE_READWRITE);
			//PBYTE challSalt = (PBYTE)XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
			//memcpy(challSalt, xke_staticSalt, 0x10);

			//MemoryBuffer mbChall;
			//if (!xbox::utilities::readFile("XeOnline:\\chall.bin", mbChall))
			//	xbox::utilities::log("failed to get challenge from storage device!");

			//ZeroMemory(challBuff, 0x1000);
			//memcpy(challBuff, mbChall.GetData(), mbChall.GetDataLength());
			//CreateXKEBuffer(challBuff, 0x1000, challSalt, NULL, NULL, NULL);
			//XPhysicalFree(challBuff);
			//XPhysicalFree(challSalt);
		}

		VOID initialize()
		{
			LPCWSTR pwszButtons[3] = { L"Redeem Code", L"Check Code", L"Cancel" };
			XamShowMessageBox(XamHudGetUserIndex(), L"XeOnline Menu", L"Please choose an option below.", ARRAYSIZE(pwszButtons), pwszButtons, 0, (MBOXRESULT)s_OnMessageBoxReturn, XMB_ALERTICON);
		}
	}
}