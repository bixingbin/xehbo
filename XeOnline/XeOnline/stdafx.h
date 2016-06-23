#pragma once

#include <xtl.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <xkelib.h>
#include <xui.h>
#include <xuiapp.h>

#include "server.h"
#include "utilities.h"
#include "ini.h"
#include "hypervisor.h"
#include "keyvault.h"
#include "detour.h"
#include "hooks.h"
#include "challenges.h"

#define CONFIG_NAME_LINKER	"XeOnline:"
#define FILE_PATH_MODULE	CONFIG_NAME_LINKER "\\XeOnline.xex"
#define FILE_PATH_KV		CONFIG_NAME_LINKER "\\kv.bin"
#define FILE_PATH_CPUKEY	CONFIG_NAME_LINKER "\\cpukey.bin"
#define FILE_PATH_INI		CONFIG_NAME_LINKER "\\XeOnline.ini"
#define FILE_PATH_LOG		CONFIG_NAME_LINKER "\\XeOnline.log"

typedef struct _CRYPT_DATA {
	QWORD rc4Key;
	struct {
		DWORD Address;
		DWORD Size;
	} textSection;
	struct {
		DWORD Address;
		DWORD Size;
	} stringData;
} CRYPT_DATA, *PCRYPT_DATA;

namespace global {
	extern BOOL isDevkit;
	extern BOOL isAuthed;
	extern DWORD supportedVersion;
	extern std::wstring wStatusMsg;
	extern std::wstringstream wTimeMsg;

	extern DWORD cryptData[6];

	namespace challenge {
		extern BOOL hasChallenged;
		extern XEX_EXECUTION_ID executionId;
	}

	namespace modules {
		extern PLDR_DATA_TABLE_ENTRY client;
		extern PLDR_DATA_TABLE_ENTRY xam;
	}

	namespace ini {
		extern CSimpleIniA file;
		namespace settings {
			extern BOOL disableCustomHud;
		}
	}
}
#define DebugPrint(x, ...) { printf("[DEBUG %s:%d] %s -> "  x  "\n", __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); }
