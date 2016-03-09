#pragma once
#include "stdafx.h"

class CXamShutdownNavButton : public CXuiNavButtonImpl
{

protected:

	// Message map.
	XUI_BEGIN_MSG_MAP()
		XUI_ON_XM_INIT(OnInit)
		XUI_ON_XM_PRESS(OnPress)
		XUI_END_MSG_MAP()

		//----------------------------------------------------------------------------------
		// Performs initialization tasks - retreives controls.
		//----------------------------------------------------------------------------------
		HRESULT OnInit(XUIMessageInit* pInitData, BOOL& bHandled)
	{
		D3DXVECTOR3 vPos;
		GetPosition(&vPos);
		vPos.y -= 28;
		SetPosition(&vPos);
		SetText(L"XeOnline Menu");
		SetShow(TRUE);

		return S_OK;
	}

	//----------------------------------------------------------------------------------
	// Handler for the button press message.
	//----------------------------------------------------------------------------------
	HRESULT OnPress(XUIMessagePress *pData, BOOL& bHandled)
	{
		//redeemToken();
		return S_OK;
	}

public:

	// Define the class. The class name must match the ClassOverride property
	// set for the scene in the UI Authoring tool.
	XUI_IMPLEMENT_CLASS(CXamShutdownNavButton, L"XamShutdownNavButton", XUI_CLASS_NAVBUTTON)
};

namespace xbox {
	namespace hooks {

		namespace titles {
			typedef enum _XBOX_GAMES : DWORD {
				SYS_DASHBOARD = 0xFFFE07D1,
				SYS_XSHELL = 0xFFFE07FF,
				COD_BLACK_OPS_2 = 0x415608C3,
				COD_GHOSTS = 0x415608FC,
				COD_AW = 0x41560914
			} XBOX_GAMES;

			VOID initialize(PLDR_DATA_TABLE_ENTRY ModuleHandle);
		}

		HRESULT initialize();
	}
}