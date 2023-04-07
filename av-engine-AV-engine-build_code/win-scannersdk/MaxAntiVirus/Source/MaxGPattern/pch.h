// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
//#include <windows.h>
//#include "atlstr.h"
#include <afx.h>
#include "SDConstants.h"

CString GetInstallPath();
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true, int iLogLevel = -1);
//void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart = 0, const DWORD dwTypeOfData = 0, const DWORD dwTypeOfScanner = 0, const TCHAR *sDataPart = 0, const TCHAR *sReplaceDataPart = 0, bool bStartingScan = true);

// TODO: reference additional headers your program requires here
