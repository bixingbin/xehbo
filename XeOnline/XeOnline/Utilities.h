#pragma once
#include "stdafx.h"

typedef struct _LAUNCH_SYS_MSG {
	XNOTIFYQUEUEUI_TYPE Type;
	PWCHAR Message;
	DWORD Delay;
} LAUNCH_SYS_MSG, *PLAUNCH_SYS_MSG;

class MemoryBuffer
{
public:

	MemoryBuffer( DWORD dwSize = 512 )
	{
		m_pBuffer = NULL;
		m_dwDataLength = 0;
		m_dwBufferSize = 0;

		if( ( dwSize < UINT_MAX ) && ( dwSize != 0 ) )
		{
			m_pBuffer = ( BYTE* )malloc( dwSize + 1 );    // one more char, in case when using string funcions
			if( m_pBuffer )
			{
				m_dwBufferSize = dwSize;
				m_pBuffer[0] = 0;
			}
		}
	};

	~MemoryBuffer()
	{
		if( m_pBuffer )
			free( m_pBuffer );

		m_pBuffer = NULL;
		m_dwDataLength = 0;
		m_dwBufferSize = 0;
	};

    // Add chunk of memory to buffer
    BOOL    Add( const void* p, DWORD dwSize )
    {
        if( CheckSize( dwSize ) )
        {
            memcpy( m_pBuffer + m_dwDataLength, p, dwSize );
            m_dwDataLength += dwSize;
            *( m_pBuffer + m_dwDataLength ) = 0;    // fill end zero
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    };

    // Get the data in buffer
    BYTE* GetData() const
    {
        return m_pBuffer;
    };

    // Get the length of data in buffer
    DWORD   GetDataLength() const
    {
        return m_dwDataLength;
    };

    // Rewind the data pointer to the begining
    void    Rewind()
    {
        m_dwDataLength = 0; m_pBuffer[ 0 ] = 0;
    };

    // Automatically adjust increase buffer size if necessary
    BOOL    CheckSize( DWORD dwSize )
    {
        if( m_dwBufferSize >= ( m_dwDataLength + dwSize ) )
        {
            return TRUE;    // Enough space
        }
        else
        {
            // Try to double it
            DWORD dwNewSize = max( m_dwDataLength + dwSize, m_dwBufferSize * 2 );
            BYTE* pNewBuffer = ( UCHAR* )realloc( m_pBuffer, dwNewSize + 1 );        // one more char
            if( pNewBuffer )
            {
                m_pBuffer = pNewBuffer;
                m_dwBufferSize = dwNewSize;
                return TRUE;
            }
            else
            {
                // Failed
                return FALSE;
            }
        }
    }

	private:

	BYTE* m_pBuffer;

    DWORD m_dwDataLength;

    DWORD m_dwBufferSize;
};

#define GetPointer(X) *(DWORD*)(X)

static BOOL(__cdecl *dlaunchSetOptValByName)(CONST PCHAR optName, PDWORD val); // set when setLiveBlock is called
static HRESULT(__cdecl *DevSetMemory)(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf, LPDWORD pcbRet); // set when xbox::utilities::setMemory is called
static LAUNCH_SYS_MSG notifyData;

namespace xbox {
	namespace utilities {
		VOID log(const CHAR* strFormat, ...);
		HRESULT setLiveBlock(BOOL enabled);
		VOID setNotifyMsg(WCHAR* msg);
		BOOL isNotifyMsgSet();
		VOID rebootToDash();
		VOID doErrShutdown(WCHAR* msg, BOOL reboot = FALSE);
		VOID patchInJump(DWORD* Address, DWORD Destination, BOOL Linked);
		VOID patchInBranch(DWORD* Address, DWORD Destination, BOOL Linked);
		FARPROC resolveFunction(CHAR* ModuleName, DWORD Ordinal);
		DWORD getModuleImportCallAddress(LDR_DATA_TABLE_ENTRY* moduleHandle, CHAR* ImportedModuleName, DWORD Ordinal);
		DWORD patchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
		DWORD patchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
		BOOL readFile(const CHAR * FileName, MemoryBuffer &pBuffer);
		BOOL writeFile(const CHAR* FilePath, const VOID* Data, DWORD Size);
		BOOL fileExists(LPCSTR lpFileName);
		HRESULT setMemory(VOID* Destination, DWORD Value);
		HRESULT setMemory(VOID* Destination, VOID* Source, DWORD Length);
		DWORD applyPatches(VOID* patches, CHAR* filePath = NULL);
		HRESULT applyDefaultPatches();
		HRESULT mountSystem();
		VOID notify(PWCHAR displayText, DWORD dwDelay = 0, XNOTIFYQUEUEUI_TYPE notifyType = XNOTIFYUI_TYPE_CONSOLEMESSAGE);
		VOID createThread(PVOID lpStartAddress, BOOL systemThread = TRUE, DWORD dwHardwareThread = 4);
	}
}