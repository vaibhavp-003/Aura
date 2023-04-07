// MaxGPattern.cpp : Defines the exported functions for the DLL application.
//

#include "pch.h"
#include "MaxGPattern.h"
#include "MaxRandomPattern.h"

CMaxRandomPattern g_objMaxRandomPattern;

extern "C" __declspec(dllexport) bool ScanPattern(TCHAR *pszFilePath)
{
	return g_objMaxRandomPattern.ScanPattern(pszFilePath);
}
//extern "C" __declspec(dllexport) bool ScanFileLessMalware(LPCTSTR szFilePath)
//{
//	return g_objMaxRandomPattern.ScanFLessMal(szFilePath);
//}
extern "C" __declspec(dllexport) bool LoadDB(TCHAR *pszDBPath, bool bScanRandPat)
{
	return g_objMaxRandomPattern.InitializeScanner(pszDBPath, bScanRandPat);
}
extern "C" __declspec(dllexport) bool UnLoadDB()
{
	return g_objMaxRandomPattern.UnloadDB();
}