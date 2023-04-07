// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MaxCertScan.h"

#define DLL_EXPORT		extern "C" __declspec(dllexport)

CMaxCertScan	g_objCertScan;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DLL_EXPORT void SetAppDataPath(LPCTSTR pszAppDataPath, LPCTSTR pszLocalAppDataPath)
{
	g_objCertScan.SetAppDataPath(pszAppDataPath, pszLocalAppDataPath);
}

DLL_EXPORT DWORD CheckFileWithPattern(LPCTSTR pFileName)
{
	DWORD dwRetValue = 0x00;
	
	if(g_objCertScan.CheckBlackFileName(pFileName) == true)
	{
		dwRetValue = 0x01;
	}

	return dwRetValue;
}

DLL_EXPORT DWORD CheckFileInAppData(LPCTSTR pFileName)
{
	DWORD dwRetValue = 0x00;

	if(g_objCertScan.CheckBlackFileInAppData(pFileName))
	{
		dwRetValue = 0x01;
	}
	return dwRetValue;
}