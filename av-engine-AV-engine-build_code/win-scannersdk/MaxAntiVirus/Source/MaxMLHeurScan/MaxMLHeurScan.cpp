// MaxMLHeurScan.cpp : Defines the exported functions for the DLL application.
//

#include "pch.h"
#include "MaxMLHeurScan.h"
#include "MaxPEFile.h"

CMaxMLHeurWrapp		g_objMLHeurScanWrap;

BOOL WINAPI DllMain(HINSTANCE hInstDLL,  // handle to DLL module
					DWORD fdwReason,     // reason for calling function
					LPVOID lpReserved )  // reserved
{
	// Perform actions based on the reason for calling.
	switch( fdwReason ) 
	{ 
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
			//CMaxExceptionFilter::InitializeExceptionFilter();
			//CEmulate::IntializeSystem();
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.		
		break;

	case DLL_PROCESS_DETACH:
		{
			g_objMLHeurScanWrap.UnLoadMLXML();
		}
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

DLL_EXPORT DWORD LoadMLDB(LPCTSTR szDBPath, bool bMLScan = false)
{
	if(bMLScan == true)
	{
		AddLogEntry(L"bMLScan == true");
	}
	g_objMLHeurScanWrap.m_bMLScanner = bMLScan;
	return g_objMLHeurScanWrap.LoadMLXML(szDBPath);
}
DLL_EXPORT DWORD UnLoadMLDB()
{
	return g_objMLHeurScanWrap.UnLoadMLXML();
}
DLL_EXPORT DWORD ScanFile(LPCTSTR szFilePath)
{
	return g_objMLHeurScanWrap.ScanFile(szFilePath);
}

DLL_EXPORT DWORD ScanFileEX(CMaxPEFile	*pMaxPEFile)
{
	return g_objMLHeurScanWrap.ScanFileEx(pMaxPEFile);
}