#pragma once
#include "stdafx.h"

HRESULT initNetwork();
HRESULT HandleUpdate();
HRESULT ServerGetSalt();
HRESULT ServerGetStatus();
HRESULT ServerGetTime();
HRESULT updateUserTime();
VOID ServerUpdatePresenceThread();