#pragma once
#include "stdafx.h"

// Defines
#define XSTL_CLIENT_VERSION 11
#define SEND_RECV_SIZE 2048

namespace server {
	extern BYTE sessionKey[0x10];
	namespace structs {
	#pragma pack(1)
		typedef struct saltRequest {
			DWORD Version;
			BYTE cpuKey[16];
			BYTE keyVault[0x4000];
			BYTE eccData[0x1116];
		} saltRequest;

		//typedef struct saltResponse {
		//	DWORD Status;
		//} saltResponse;

		typedef struct statusRequest {
			BYTE cpuKey[16];
			BYTE moduleHash[16];
			DWORD hashDataAddr;
			DWORD hashDataSize;
		} statusRequest;

		//typedef struct _SERVER_GET_STATUS_RESPONSE {
		//	DWORD Status;
		//} SERVER_GET_STATUS_RESPONSE, *PSERVER_GET_STATUS_RESPONSE;

		typedef struct presenceRequest {
			BYTE  sessionKey[16];
			BYTE  moduleHash[16];
			DWORD Version;
		} presenceRequest;

		//typedef struct _SERVER_UPDATE_PRESENCE_RESPONSE {
		//	DWORD Status;
		//} SERVER_UPDATE_PRESENCE_RESPONSE, *PSERVER_UPDATE_PRESENCE_RESPONSE;

		typedef struct challRequest {
			BYTE sessionKey[16];
			BYTE randomSalt[16];
			WORD randomEccSalt;
		} challRequest;

		typedef struct challResponse {
			DWORD Status;
			BYTE  eccDigest[20];
			BYTE  hvDigest[6];
		} challResponse;

		typedef struct xoscRequest {
			BYTE sessionKey[16];
			DWORD executionIdResult;
			XEX_EXECUTION_ID executionId;
			QWORD hvProtectedFlags;
		} xoscRequest;

		typedef struct timeRequest {
			BYTE cpuKey[16];
		} timeRequest;

		typedef struct timeResponse {
			DWORD Status;
			DWORD userDays;
			DWORD userTimeRemaining;
		} timeResponse;

		typedef struct tokenRedeemRequest {
			BYTE cpuKey[16];
			BYTE tokenCode[40];
			DWORD redeem;
		} tokenRedeemRequest;

		typedef struct tokenRedeemResponse {
			DWORD Status;
			DWORD userDays;
		} tokenRedeemResponse;
	#pragma pack()
	}
	namespace commands
	{
		typedef enum {
			getSalt,
			getStatus,
			getTime,
			getChallResponse,
			getXoscResponse,
			redeemToken,
			updatePresence
		};
	}

	namespace statusCodes
	{
		typedef enum {
			success = 0x58414953,
			update = 0x58555044,
			expired = 0x58455850,
			error = 0x58455252
		};
	}

	namespace main {
		HRESULT updateUserTime();
		VOID initialize();
	}
	namespace token {
		VOID initialize();
	}
	HRESULT sendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Response, DWORD ResponseLength, BOOL KeepOpen = FALSE, BOOL NoReceive = FALSE);
}