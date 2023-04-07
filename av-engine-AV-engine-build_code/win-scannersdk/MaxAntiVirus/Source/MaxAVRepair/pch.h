
#pragma once
#include <windows.h>
#include <tchar.h>

void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true);
void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart = 0, const DWORD dwTypeOfData = 0, const DWORD dwTypeOfScanner = 0, const TCHAR *sDataPart = 0, const TCHAR *sReplaceDataPart = 0, bool bStartingScan = true);
