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

DLL_EXPORT DWORD IsWhitePublisher(LPCTSTR pFileName)
{
	DWORD	dwRetValue = 0x00;

	if (g_objCertScan.CheckKnownPublisher(pFileName) == true)
	{
		dwRetValue = 0x01;
	}

	return dwRetValue;
}

DLL_EXPORT void SetFilterINI(LPCTSTR pFileName)
{
	g_objCertScan.FilterINI(pFileName);
}

DLL_EXPORT DWORD ExpressionParsing(LPCTSTR pFileName)
{
	DWORD	dwRetValue = 0x00;

	if (g_objCertScan.CheckKnownFileName(pFileName) == true)
	{
		dwRetValue = 0x01;
	}

	return dwRetValue;
}