
#pragma once

//THIS FILE IS USED BY BOTH DBScan CODE AND PMScan CODE
#ifdef MAXAVDBSCAN_EXPORTS
#define WINVER	0x600

#include <afx.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <tchar.h>
#include <atlbase.h>
#include <math.h>
#include <time.h>
#include <shobjidl.h>
#include <shlguid.h>

#include "SDConstants.h"
#include "MaxConstant.h"
#include "MaxExceptionFilter.h"
#include "ScriptSig.h"

CString GetInstallPath();

void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true, int iLogLevel = -1);
void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart = 0, const DWORD dwTypeOfData = 0, const DWORD dwTypeOfScanner = 0, const TCHAR *sDataPart = 0, const TCHAR *sReplaceDataPart = 0, bool bStartingScan = true);
#else
//#include <windef.h>
//#include <winnt.h>
//#include <winbase.h>
#pragma once
#include <windows.h>
#include <tchar.h>
#include <stdlib.h>

void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true);
void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart = 0, const DWORD dwTypeOfData = 0, const DWORD dwTypeOfScanner = 0, const TCHAR *sDataPart = 0, const TCHAR *sReplaceDataPart = 0, bool bStartingScan = true);
#endif
