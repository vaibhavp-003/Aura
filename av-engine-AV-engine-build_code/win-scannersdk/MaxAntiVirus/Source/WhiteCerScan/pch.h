// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <stdlib.h>
#include <windows.h>
#include <wchar.h>
#include <tchar.h>




// TODO: reference additional headers your program requires here
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true);
void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart = 0, const DWORD dwTypeOfData = 0, const DWORD dwTypeOfScanner = 0, const TCHAR *sDataPart = 0, const TCHAR *sReplaceDataPart = 0, bool bStartingScan = true);
