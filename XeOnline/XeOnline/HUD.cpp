#include "stdafx.h"

extern BOOL isDevkit;
extern PLDR_DATA_TABLE_ENTRY hClient;
extern PLDR_DATA_TABLE_ENTRY hXam;
extern WCHAR wNotifyMsg[100];
extern Detour<HRESULT> *XuiPNGTextureLoaderDetour;

CXamShutdownNavButton btnXam;

HRESULT XuiRegisterClassHook(const XUIClass *pClass, HXUICLASS *phClass)
{
	if (wcscmp(pClass->szClassName, L"ShutdownNavButton") == 0)
		btnXam.Register();

	return XuiRegisterClass(pClass, phClass);
}

HRESULT XuiUnregisterClassHook(LPCWSTR szClassName)
{
	if (wcscmp(szClassName, L"ShutdownNavButton") == 0)
		btnXam.Unregister();

	return XuiUnregisterClass(szClassName);
}

//HRESULT XuiSceneCreateHook(PWCHAR szBasePath, PWCHAR szScenePath, void* pvInitData, HXUIOBJ* phScene)
//{
//	printf("Loading %ls\n", szScenePath);
//
//	WCHAR xblseSection[50];
//	RtlSnwprintf(xblseSection, 50, L"section://%X,xui#GuideMain_xbls.xur", hClient);
//
//	if (wcscmp(szScenePath, L"GuideMain.xur") == 0)
//		return XuiSceneCreate(0, xblseSection, pvInitData, phScene);
//
//	if (wcscmp(szBasePath, xblseSection) == 0)
//		RtlSnwprintf(szBasePath, 50, L"section://@0,hud#");
//
//	HRESULT result = XuiSceneCreate(szBasePath, szScenePath, pvInitData, phScene);
//
//	/*if (wcscmp(szScenePath, L"GuideMain.xur") == 0)
//	{
//		updateUserTime();
//
//		HXUIOBJ hTabscene;
//		XuiElementGetFirstChild(*phScene, &hTabscene);
//
//		HXUIOBJ txtTimeRemaining, txtUserStatus;
//		XuiElementGetChildById(hTabscene, L"txt_TimeRemaining", &txtTimeRemaining);
//		XuiElementGetChildById(hTabscene, L"txt_UserStatus", &txtUserStatus);
//
//		XuiTextElementSetText(txtTimeRemaining, wNotifyMsg);
//		XuiTextElementSetText(txtUserStatus, L"Disconnected");
//
//	}
//	else */if (wcsstr(szScenePath, L"SettingsTabSigned") != 0)
//	{
//		HXUIOBJ btnXamShutdown;
//		XuiElementGetChildById(*phScene, L"btnXamShutdown", &btnXamShutdown);
//		btnXam.Attach(btnXamShutdown);
//	}
//
//	return result;
//}

HRESULT XuiSceneCreateHook(PWCHAR szBasePath, PWCHAR szScenePath, void* pvInitData, HXUIOBJ* phScene)
{
	printf("Loading %ls\n", szScenePath);

	HRESULT result = XuiSceneCreate(szBasePath, szScenePath, pvInitData, phScene);

	if (wcscmp(szScenePath, L"GuideMain.xur") == 0)
	{
		updateUserTime();

		// Set header text
		HXUIOBJ headerLabel;
		XuiElementGetChildById(*phScene, L"Header", &headerLabel);
		XuiControlSetText(headerLabel, L"XeOnline Guide");

		// get Tabscene
		HXUIOBJ hTabscene;
		XuiElementGetFirstChild(*phScene, &hTabscene);

		#pragma region change_highlighted_text_color
		HXUIOBJ txtGamesSel, txtHomeSel, txtMediaSel, txtSystemSel;
		XUIElementPropVal propVal;
		DWORD propId = 0;

		propVal.SetColorVal(0xFF2980B9);

		XuiElementGetChildById(hTabscene, L"txt_gamesSel", &txtGamesSel);
		XuiObjectGetPropertyId(txtGamesSel, L"TextColor", &propId);
		XuiObjectSetProperty(txtGamesSel, propId, 0, &propVal);

		XuiElementGetChildById(hTabscene, L"txt_homeSel", &txtHomeSel);
		XuiObjectGetPropertyId(txtHomeSel, L"TextColor", &propId);
		XuiObjectSetProperty(txtHomeSel, propId, 0, &propVal);

		XuiElementGetChildById(hTabscene, L"txt_MediaSel", &txtMediaSel);
		XuiObjectGetPropertyId(txtMediaSel, L"TextColor", &propId);
		XuiObjectSetProperty(txtMediaSel, propId, 0, &propVal);

		XuiElementGetChildById(hTabscene, L"txt_SystemSel", &txtSystemSel);
		XuiObjectGetPropertyId(txtSystemSel, L"TextColor", &propId);
		XuiObjectSetProperty(txtSystemSel, propId, 0, &propVal);
		#pragma endregion

		#pragma region custom_text
		HXUIOBJ txtTimeRemaining, txtUserStatus;

		/// txtTimeRemaining
		XuiCreateObject(XUI_CLASS_TEXT, &txtTimeRemaining);
		XuiElementSetBounds(txtTimeRemaining, 313.0, 20.0);
		XuiElementSetPosition(txtTimeRemaining, &D3DXVECTOR3(243, 375, 0));

		// Set Color
		propVal.SetColorVal(0xFF00FF00);
		XuiObjectGetPropertyId(txtTimeRemaining, L"TextColor", &propId);
		XuiObjectSetProperty(txtTimeRemaining, propId, 0, &propVal);

		// Set font size
		propVal.SetVal(10.0f);
		XuiObjectGetPropertyId(txtTimeRemaining, L"PointSize", &propId);
		XuiObjectSetProperty(txtTimeRemaining, propId, 0, &propVal);

		// set text and add to scene
		XuiTextElementSetText(txtTimeRemaining, wNotifyMsg);
		XuiElementAddChild(hTabscene, txtTimeRemaining);

		/// txtUserStatus
		XuiCreateObject(XUI_CLASS_TEXT, &txtUserStatus);
		XuiElementSetBounds(txtUserStatus, 313.0, 20.0);
		XuiElementSetPosition(txtUserStatus, &D3DXVECTOR3(243, 395, 0));

		// Set Color
		propVal.SetColorVal(0xFF00FF00);
		XuiObjectGetPropertyId(txtUserStatus, L"TextColor", &propId);
		XuiObjectSetProperty(txtUserStatus, propId, 0, &propVal);

		// Set font size
		propVal.SetVal(10.0f);
		XuiObjectGetPropertyId(txtUserStatus, L"PointSize", &propId);
		XuiObjectSetProperty(txtUserStatus, propId, 0, &propVal);

		// set text and add to scene
		XuiTextElementSetText(txtUserStatus, L"Connected");
		XuiElementAddChild(hTabscene, txtUserStatus);
		#pragma endregion
	}
	else if (wcsstr(szScenePath, L"SettingsTabSigned") != 0)
	{
		HXUIOBJ btnXamShutdown;
		XuiElementGetChildById(*phScene, L"btnXamShutdown", &btnXamShutdown);
		btnXam.Attach(btnXamShutdown);
	}

	return result;
}

HRESULT XuiPNGTextureLoaderHook(IXuiDevice *pDevice, LPCWSTR szFileName, XUIImageInfo *pImageInfo, IDirect3DTexture9 **ppTex)
{
	printf("[XuiPNGTextureLoaderHook]: %ls\n", szFileName);
	WCHAR sectionFile[50];
	
	if (wcscmp(szFileName, L"skin://Blade_grey.png") == 0)
		XamBuildResourceLocator(hClient, L"xui", L"Blade_grey.png", sectionFile, 50);
	else if (wcscmp(szFileName, L"xam://xenonLogo.png") == 0)
		XamBuildResourceLocator(hClient, L"xui", L"xenonLogo.png", sectionFile, 50);
	
	return XuiPNGTextureLoaderDetour->CallOriginal(pDevice, wcslen(sectionFile) > 5 ? sectionFile : szFileName, pImageInfo, ppTex);
}

HRESULT setupCustomSkin(HANDLE hModule, PWCHAR wModuleName, PWCHAR const cdModule, PWCHAR hdRes, DWORD dwSize)
{
	XamBuildResourceLocator(hClient, L"xui", L"skin.xur", hdRes, 80);
	return XuiLoadVisualFromBinary(hdRes, 0);
}

VOID patchHud(PLDR_DATA_TABLE_ENTRY hModule)
{
	PatchModuleImport(hModule, MODULE_XAM, 842, (DWORD)XuiRegisterClassHook);
	PatchModuleImport(hModule, MODULE_XAM, 855, (DWORD)XuiSceneCreateHook);
	PatchModuleImport(hModule, MODULE_XAM, 866, (DWORD)XuiUnregisterClassHook);
}