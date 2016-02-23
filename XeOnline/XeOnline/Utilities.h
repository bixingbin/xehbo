#pragma once
#include "stdafx.h"

#define GetPointer(X) *(DWORD*)(X)

// lets you get/set option values by their ini name, returns TRUE if successful and FALSE if not
typedef BOOL(*DLAUNCHGETOPTVALBYNAME)(char* optName, PDWORD val);
typedef BOOL(*DLAUNCHSETOPTVALBYNAME)(char* optName, PDWORD val);
static DLAUNCHGETOPTVALBYNAME dlaunchGetOptValByName = NULL;
static DLAUNCHSETOPTVALBYNAME dlaunchSetOptValByName = NULL;

typedef enum
{
	DL_ORDINALS_LDAT = 1,
	DL_ORDINALS_STARTSYSMOD,
	DL_ORDINALS_SHUTDOWN,
	DL_ORDINALS_FORCEINILOAD,
	DL_ORDINALS_GETNUMOPTS,
	DL_ORDINALS_GETOPTINFO,
	DL_ORDINALS_GETOPTVAL,
	DL_ORDINALS_SETOPTVAL,
	DL_ORDINALS_GETOPTVALBYNAME,
	DL_ORDINALS_SETOPTVALBYNAME,
	DL_ORDINALS_GETDRIVELIST,
	DL_ORDINALS_GETDRIVEINFO,
} DL_ORDINALS;

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

VOID DbgLog(const CHAR* strFormat, ...);
HRESULT XZPGetFile(LPCWSTR szFile, CONST BYTE **pSectionData, DWORD* pSectionSize);

PBYTE getCpuKey();
HRESULT setLiveBlock(BOOL enabled);

VOID setNotifyMsg(WCHAR* msg);
BOOL isNotifyMsgSet();
VOID doErrShutdown(WCHAR* msg, BOOL reboot = FALSE);
VOID printBytes(PBYTE bytes, DWORD len);

BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa);
VOID PatchInJump(DWORD* Address, DWORD Destination, BOOL Linked);
VOID PatchInBranch(DWORD* Address, DWORD Destination, BOOL Linked);
DWORD makeBranch(DWORD branchAddr, DWORD destination, BOOL linked);
FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal);
DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
VOID HookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest);
HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System);
HRESULT DeleteSymbolicLink(CHAR* szDrive, BOOL System);
BOOL CReadFile(const CHAR * FileName, MemoryBuffer &pBuffer);
BOOL CWriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size);
BOOL FileExists(LPCSTR lpFileName);
HRESULT SetMemory(VOID* Destination, VOID* Source, DWORD Length);
DWORD ApplyPatches(CHAR* FilePath, const VOID* DefaultPatches = NULL);
VOID XNotifyUI(PWCHAR displayText, DWORD dwDelay = 0, XNOTIFYQUEUEUI_TYPE notifyType = XNOTIFYUI_TYPE_CONSOLEMESSAGE);
VOID launchSysThread(LPTHREAD_START_ROUTINE func);