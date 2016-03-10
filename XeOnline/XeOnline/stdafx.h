#pragma once

#include <xtl.h>
#include <fstream>
#include <xkelib.h>
#include <xui.h>
#include <xuiapp.h>

#include "server.h"
#include "utilities.h"
#include "hypervisor.h"
#include "keyvault.h"
#include "detour.h"
#include "hooks.h"
#include "challenges.h"

using namespace std;

#define CONFIG_NAME_LINKER	"XeOnline:"
#define FILE_PATH_KV		CONFIG_NAME_LINKER "\\KV.bin"
#define FILE_PATH_CPUKEY	CONFIG_NAME_LINKER "\\CPUKey.bin"
#define FILE_PATH_LOG		CONFIG_NAME_LINKER "\\XeOnline.log"

static DWORD cryptData[6] = { 0x78624372, 0x7970746F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF }; // KEY | ADDRESS | SIZE | ADDRESS | SIZE

namespace global {
	extern BOOL isDevkit;
	extern BOOL isAuthed;
	extern DWORD supportedVersion;
	extern WCHAR wNotifyMsg[100];

	namespace challenge {
		extern PVOID bufferAddress;
		extern DWORD bufferSize;
		extern BOOL hasChallenged;
		extern PBYTE cleanCacheBuffer;
		extern PBYTE cleanHvBuffer;
		extern XEX_EXECUTION_ID executionId;
		extern XECRYPT_SHA_STATE xShaCurrentXex;
	}

	namespace modules {
		extern PLDR_DATA_TABLE_ENTRY client;
		extern PLDR_DATA_TABLE_ENTRY xam;
	}
}