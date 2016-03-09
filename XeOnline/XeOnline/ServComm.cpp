#include "stdafx.h" 
#include "ServComm.h" 

#define SEND_RECV_SIZE 2048

SOCKET hSocket = INVALID_SOCKET;
BYTE rc4Key[0x10];

HRESULT StartupServerCommunicator()
{
	XNADDR titleAddr;
	for (int i = 0; i < 30; i++)
	{
		XNetGetTitleXnAddr(&titleAddr);

		if (titleAddr.ina.S_un.S_addr != 0)
			break;
		
		Sleep(1000);
	}

	if (titleAddr.ina.S_un.S_addr == 0)
		return E_FAIL;

	XeCryptSha((PBYTE)"XeOnline", 8, NULL, NULL, NULL, NULL, rc4Key, 0x10);
	return S_OK;
}

HRESULT InitCommand()
{
	// Startup WSA
	WSADATA wsaData;
	if (NetDll_WSAStartupEx(XNCALLER_SYSAPP, MAKEWORD(2, 2), &wsaData, 0x2043C500) != 0)
		return E_FAIL;

	// Create TCP/IP socket
    if((hSocket = NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return E_FAIL;

	// disable socket encryption
	BOOL bSockOpt = TRUE;
	if (NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_MARKINSECURE, (PCSTR)&bSockOpt, sizeof(BOOL)) != 0)
		return E_FAIL;

	// set socket timeout
	DWORD timeout = 5000;
	if(NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_RCVTIMEO, (PCSTR)&timeout, sizeof(DWORD)) != 0) return E_FAIL;
	if(NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_SNDTIMEO, (PCSTR)&timeout, sizeof(DWORD)) != 0) return E_FAIL;

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

VOID EndCommand()
{
	if (hSocket != INVALID_SOCKET)
	{
		NetDll_shutdown(XNCALLER_SYSAPP, hSocket, SD_BOTH);
		NetDll_closesocket(XNCALLER_SYSAPP, hSocket);
		hSocket = INVALID_SOCKET;
	}
}

HRESULT ReceiveData(VOID* Buffer, DWORD BytesExpected)
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

HRESULT SendData(DWORD CommandId, VOID* CommandData, DWORD DataLen)
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

HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Response, DWORD ResponseLength, BOOL KeepOpen, BOOL NoReceive)
{
	// try to connect to server
	for (int i = 0; i < 10; i++)
	{
		EndCommand();
		if (InitCommand() == S_OK) break;
		else if (i == 9) return E_FAIL;
		Sleep(1000);
	}

	// try to send data, if it doesnt send then fail
	for (int i = 0; i < 10; i++)
	{
		if (SendData(CommandId, CommandData, CommandLength) == S_OK) break;
		else if (i == 9) return E_FAIL;
		Sleep(1000);
	}

	if (!NoReceive)
	{
		// Now lets get our response
		if (ReceiveData(Response, ResponseLength) != S_OK)
			return E_FAIL;
	}

	if (!KeepOpen)
		EndCommand();

	return S_OK;
}