#include "stdafx.h"

namespace xbox {
	namespace ini {
		HRESULT initialize() {
			global::ini::file.SetUnicode();
			global::ini::file.LoadFile(FILE_PATH_INI);

			if (global::ini::file.IsEmpty())
				global::ini::file.SetBoolValue("settings", "disableCustomHud", FALSE);

			global::ini::settings::disableCustomHud = global::ini::file.GetBoolValue("settings", "disableCustomHud", FALSE);
			global::ini::file.SaveFile(FILE_PATH_INI);
			return S_OK;
		}
	}
}