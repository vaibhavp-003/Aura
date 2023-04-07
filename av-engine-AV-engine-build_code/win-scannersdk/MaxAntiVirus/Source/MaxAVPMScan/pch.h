// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

#include <windows.h>
#include <tchar.h>

#define SETTING_FOLDER			_T("setting\\")
#define CURRENT_SETTINGS_INI	_T("CurrentSettings.ini") //this file can contain any current settings for any product. : Avinash Bhardwaj
#define SETTING_VAL_INI			_T("Settings")

void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1 = 0, const TCHAR *sEntry2 = 0, bool isDateTime = true);
void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart = 0, const DWORD dwTypeOfData = 0, const DWORD dwTypeOfScanner = 0, const TCHAR *sDataPart = 0, const TCHAR *sReplaceDataPart = 0, bool bStartingScan = true);
