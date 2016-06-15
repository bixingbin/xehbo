#include "stdafx.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

namespace global {
	BOOL isDevkit;
	BOOL isAuthed;
	DWORD supportedVersion = 17502;
	WCHAR wNotifyMsg[100];
	DWORD dwTest;
	//CRYPT_DATA cryptData = {
	//	0x786243727970746F,
	//	0xAAAAAAAA,
	//	0xBBBBBBBB,
	//	0xCCCCCCCC,
	//	0xDDDDDDDD
	//};
	DWORD cryptData[6] = { 0x78624372, 0x7970746F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF }; // KEY | ADDRESS | SIZE | ADDRESS | SIZE

	namespace challenge {
		BOOL hasChallenged;
		XEX_EXECUTION_ID executionId = {
			0, // media id
			XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe, // version
			XboxKrnlVersion->Major << 28 | supportedVersion << 8 | XboxKrnlVersion->Qfe, // base version
			0xFFFE07D1, // title id
			0, 0, 0, 0, 0 // other shit
		};
	}

	namespace modules {
		PLDR_DATA_TABLE_ENTRY client;
		PLDR_DATA_TABLE_ENTRY xam;
	}
}
