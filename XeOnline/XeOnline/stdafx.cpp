#include "stdafx.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

namespace global {
	BOOL isDevkit;
	BOOL isAuthed;
	DWORD supportedVersion = 17489;
	WCHAR wNotifyMsg[100];

	namespace challenge {
		PVOID bufferAddress;
		DWORD bufferSize;
		BOOL hasChallenged;
		PBYTE cleanCacheBuffer;
		PBYTE cleanHvBuffer;
		XEX_EXECUTION_ID executionId = {
			0, // media id
			XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe, // version
			XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe, // base version
			0xFFFE07D1, // title id
			0, 0, 0, 0, 0 // other shit
		};
		XECRYPT_SHA_STATE xShaCurrentXex;
	}

	namespace modules {
		PLDR_DATA_TABLE_ENTRY client;
		PLDR_DATA_TABLE_ENTRY xam;
	}
}
