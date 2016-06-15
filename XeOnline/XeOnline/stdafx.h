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
#include "hypervisor.h"
#include "keyvault.h"
#include "detour.h"
#include "hooks.h"
#include "challenges.h"

using namespace std;
#define CONFIG_NAME_LINKER	"XeOnline:"
#define FILE_PATH_MODULE	CONFIG_NAME_LINKER "\\XeOnline.xex"
#define FILE_PATH_KV		CONFIG_NAME_LINKER "\\KV.bin"
#define FILE_PATH_CPUKEY	CONFIG_NAME_LINKER "\\CPUKey.bin"
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
	extern WCHAR wNotifyMsg[100];
	extern DWORD dwTest;
	//extern CRYPT_DATA cryptData;
	extern DWORD cryptData[6];

	namespace challenge {
		extern BOOL hasChallenged;
		extern XEX_EXECUTION_ID executionId;
	}

	namespace modules {
		extern PLDR_DATA_TABLE_ENTRY client;
		extern PLDR_DATA_TABLE_ENTRY xam;
	}
}