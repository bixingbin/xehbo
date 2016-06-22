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
		server::token::initialize();
		return S_OK;
	}

public:

	// Define the class. The class name must match the ClassOverride property
	// set for the scene in the UI Authoring tool.
	XUI_IMPLEMENT_CLASS(CXamShutdownNavButton, L"XamShutdownNavButton", XUI_CLASS_NAVBUTTON)
};

typedef enum _XPRIVILEGE_TYPE_NEW
{
	_XPRIVILEGE_ADD_FRIEND = 255, // Add Friends

								  // Sessions
	_XPRIVILEGE_MULTIPLAYER_SESSIONS = 254,
	_XPRIVILEGE_MULTIPLAYER_ENABLED_BY_TIER = 253,

	// Communications
	_XPRIVILEGE_COMMUNICATIONS = 252,
	_XPRIVILEGE_COMMUNICATIONS_FRIENDS_ONLY = 251,

	_XPRIVILEGE_VIDEO_MESSAGING_SEND = 250, // sending video messages is restricted by tier and needs a second bit

											// Profile
	_XPRIVILEGE_PROFILE_VIEWING = 249,
	_XPRIVILEGE_PROFILE_VIEWING_FRIENDS_ONLY = 248,

	// Viewing of User Created Content
	_XPRIVILEGE_USER_CREATED_CONTENT = 247,
	_XPRIVILEGE_USER_CREATED_CONTENT_FRIENDS_ONLY = 246,

	_XPRIVILEGE_PURCHASE_CONTENT = 245, // Premium Content Purchases

										// Presence
	_XPRIVILEGE_PRESENCE = 244,
	_XPRIVILEGE_PRESENCE_FRIENDS_ONLY = 243,

	_XPRIVILEGE_XBOX1_LIVE_ACCESS = 242, // Xbox1 Live Access

	_XPRIVILEGE_CROSS_PLATFORM_MULTIPLAYER = 241, // Cross platform gameplay (PCs <-> Consoles)

	_XPRIVILEGE_CROSS_PLATFORM_SYSTEM_COMMUNICATION = 240, // Cross platform system communication (PCs <-> Consoles)

	_XPRIVILEGE_PREVIOUS_LIVE_PROTOCOLS = 239, // Only users on consoles flagged for selective updates will have this

	_XPRIVILEGE_TRADE_CONTENT = 238, // Player-to-player trading

	_XPRIVILEGE_MUSIC_EXPLICIT_CONTENT = 237, // explicit content

	_XPRIVILEGE_TESTER_ACCESS = 236, // Ability to test beta Live features - on (allow) | off (disallow)

									 // Video Communications
	_XPRIVILEGE_VIDEO_COMMUNICATIONS = 235,
	_XPRIVILEGE_VIDEO_COMMUNICATIONS_FRIENDS_ONLY = 234,

	_XPRIVILEGE_SHARE_WLID_WITH_FRIENDS = 233, // Discoverability - let XBL-Friends send me a WL-Buddy request - on (allow) | off (disallow)

	_XPRIVILEGE_SHARE_GAMERTAG_WITH_BUDDIES = 232, // Discoverability - let WL-Buddies send me an XBL-Friend request - on (allow) | off (disallow)

	_XPRIVILEGE_METRO_ACCESS = 231, // on (allow) | off (disallow)

	_XPRIVILEGE_SHARE_FRIENDS_LIST = 230, // on (allow) | off (disallow)

	_XPRIVILEGE_SHARE_FRIENDS_LIST_FRIENDS_ONLY = 229, // on (allow) | off (disallow)

	_XPRIVILEGE_PASSPORT_SWITCHING = 228, // Allow passport switching - on (allow) | off (disallow)

	_XPRIVILEGE_BILLING_SWITCHING = 227, // Allow user to manage their payment instruments - on (allow) | off (disallow)

	_XPRIVILEGE_MULTIPLAYER_DEDICATED_SERVER = 226, // Use of dedicated servers for multiplayer games (mainly PCs) - on (allow) | off (disallow)

	_XPRIVILEGE_USER_GRADUATION = 225, // user has a child account and is eligible to graduate - on (allow) | off (disallow)

	_XPRIVILEGE_PREMIUM_VIDEO = 224, // access to media apps, now obsolete - on (allow) | off (disallow)

	_XPRIVILEGE_PRIMETIME = 223, // access to Xbox Live Primetime (Server-Backed Games) - on (allow) | off (disallow)

	_XPRIVILEGE_CONTENT_AUTHOR = 222, // user can publish content to their console - on (allow) | off (disallow)

	_XPRIVILEGE_PII_ACCESS = 221, // user can query user PII - on (allow) | off (disallow)

	_XPRIVILEGE_SOCIAL_NETWORK_SHARING = 220, // user can change their social network discoverability - on (allow) | off (disallow)

	_XPRIVILEGE_SUBSCRIPTION_TITLE = 219, // user has subscription title privilege - true | false

	_XPRIVILEGE_SUBSCRIPTION_CONTENT = 218, // user has subscription content privilege - true | false

	_XPRIVILEGE_PURCHASE_CONTENT_REQUIRES_PIN = 217, // purchase privilege can be onbtained with pin - true | false

	_XPRIVILEGE_PASSPORT_SWITCHING_REQUIRES_PIN = 216, // passport switching can be obtained with pin - true | false

	_XPRIVILEGE_BILLING_SWITCHING_REQUIRES_PIN = 215, // billing switching can be obtain with pin - true | false

	_XPRIVILEGE_PREMIUM_CONTENT = 214, // user is entitled to premium content - true | false

	_XPRIVILEGE_FAMILY = 213, // user is entitled to family subscription functionality (family center) - true | false

	_XPRIVILEGE_UNSAFE_PROGRAMMING = 212, // unsafe or family programming for the user - on (regular programming) | off (family programming)

	_XPRIVILEGE_SHARE_CONTENT = 211, // user is allowed to upload content to external providers - on (allow) | off (disallow)

	_XPRIVILEGE_SUPPORT_OVERRIDE = 210, // used by customer support personnel to override default behaviour - on (allow) | off (disallow)

	_XPRIVILEGE_CLOUD_SAVED_GAMES = 209, // user is allowed to save games in cloud storage - on (allow) | off (disallow)

} XPRIVILEGE_TYPE_NEW;

namespace xbox {
	namespace hooks {

		namespace titles {
			typedef enum _XBOX_GAMES : DWORD {
				SYS_DASHBOARD = 0xFFFE07D1,
				SYS_XSHELL = 0xFFFE07FF,
				COD_BO2 = 0x415608C3,
				COD_GHOSTS = 0x415608FC,
				COD_AW = 0x41560914,
				COD_BO3 = 0x4156091D
			} XBOX_GAMES;

			VOID initialize(PLDR_DATA_TABLE_ENTRY ModuleHandle);
		}

		HRESULT initialize();
	}
}