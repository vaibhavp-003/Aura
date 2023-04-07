// LiveUpdateDLL.cpp : Defines the exported functions for the DLL application.
//

#include "pch.h"
#include "LiveUpdateDLL.h"
//#include "MaxClientInfoMgr.h"
#include "CommonFileIntegrityCheck.h"
#include "ExecuteProcess.h"

CLiveUpdateDLL theApp;

extern "C" { int _afxForceUSRDLL; } 
#define MAXLIVEUPDATE_API extern "C" __declspec(dllexport)


//MAXLIVEUPDATE_API BOOL StartLiveUpdate(SENDSDKLVMESSAGEUI pSendMessageToUI, LPVOID *pParam)
MAXLIVEUPDATE_API int StartLiveUpdate(SENDSDKLVMESSAGEUI pSendMessageToUI, int iUpdateOption)
{
	//ZeroMemory(&m_pUpdateInfo, sizeof(UPDATE_OPTIONS));

	int iRet = theApp.m_objLiveUpdtate.Update(pSendMessageToUI, iUpdateOption);
	return iRet;
}
 
MAXLIVEUPDATE_API bool StopLiveUpdate()
{
	if(theApp.m_objLiveUpdtate.StopLiveUpdate())
	{
		return true;
	}
	return false;
}


/*MAXLIVEUPDATE_API BOOL StartLiveUpdate( LPVOID *pParam)
{
	CLiveUpdate objLiveUpdtate;
	if(objLiveUpdtate.Update(pParam))
	{
		return TRUE;
	}
	return FALSE;
}*/
CLiveUpdateDLL::CLiveUpdateDLL()
{
	m_bNewDBFileDownloaded = false;
	m_bLiveUpdateUpToDate = FALSE;
	m_bDatabasePatch = false;
	m_bAutoUpdate = false;
	m_bManualUpdate = false;
	m_bLocalServerUpdate = false;
	m_bIsLocalServer = false;
	m_bFullUpdate = false;
	m_bProductPatch = false;
	m_bFullDataProductUpdates = false;
	m_bStandaloneDownload = false;
	m_bControlServerDownload = false;
	m_bOtherProductDownload = false;
	m_bAutoRollBack = false;
	m_bSoftwareUpdate = false;
	m_bLocalServerUpdate = false;
}

CLiveUpdateDLL::~CLiveUpdateDLL()
{
	
}

BOOL CLiveUpdateDLL::InitInstance()
{
	CWinApp::InitInstance();
	LoadLoggingLevel();
	return TRUE;
}
int CLiveUpdateDLL::ExitInstance()
{
	
	return CWinApp::ExitInstance();
}


void CLiveUpdateDLL::ReadAllSectionNameFromIni()
{
	CCommonFunctions objCommonFunctions;
	m_csUpdtVerDetails = objCommonFunctions.GetSectionName(_T("UPDATEVERSION"));
	m_csDeltaDetails = objCommonFunctions.GetSectionName(_T("DELTADETAILS"));
	m_csDatabaseDetails = objCommonFunctions.GetSectionName(_T("DATABASEKEY"));
	m_csVirusDetails = objCommonFunctions.GetSectionName(_T("VIRUSKEY"));
	m_csProductDetails = objCommonFunctions.GetSectionName(_T("PRODUCTKEY"));
}


/********for X64***********/
void CLiveUpdateDLL::ReadAllSectionNameFromIniX64()
{
	CCommonFunctions objCommonFunctionsX64;

	m_csUpdtVerDetailsX64 = objCommonFunctionsX64.GetSectionNameForX64(_T("UPDATEVERSION"));
	m_csDeltaDetails = objCommonFunctionsX64.GetSectionNameForX64(_T("DELTADETAILS"));
	m_csDatabaseDetails = objCommonFunctionsX64.GetSectionNameForX64(_T("DATABASEKEY"));
	m_csVirusDetailsX64 = objCommonFunctionsX64.GetSectionNameForX64(_T("VIRUSKEY"));
	m_csProductDetailsX64 = objCommonFunctionsX64.GetSectionNameForX64(_T("PRODUCTKEY"));
}

bool CLiveUpdateDLL::InitLiveUpdate()
{
	bool bRet = true;
	CRegistry objReg;

	m_iIsUIProduct = 1;
	m_csUpdtVerDetails = _T("");
	m_csDatabaseDetails = _T("");
	m_csVirusDetails = _T("");
	m_csProductDetails = _T("");
	m_csDatabaseDetailsCL = _T("");
	m_csUpdtVerDetailsX64 = _T("");
	m_csDatabaseDetails = _T("");
	m_csVirusDetailsX64 = _T("");
	m_csProductDetailsX64 = _T("");
	m_csDeltaDetails = _T("");

	m_bLocalServerUpdate = false;
	m_bExitThread = false;

	m_csWaitingForMergePath = CSystemInfo::m_strWaitingForMerge;
	
	CreateDirectory(CSystemInfo::m_strWaitingForMerge, NULL);
	CreateDirectory(CSystemInfo::m_strWaitingForMerge + L"\\Data", NULL);
	CreateDirectory(CSystemInfo::m_strTempLiveupdate, NULL);
	CreateDirectory(CSystemInfo::m_strTempLiveupdate + L"\\DownloadTempFiles\\", NULL);
	//AfxMessageBox(CSystemInfo::m_strTempLiveupdate + L"\\DownloadTempFiles\\");
	
#ifdef WIN64
	ReadAllSectionNameFromIniX64();
#else
	ReadAllSectionNameFromIni();
#endif


	CString csCommandLine = GetCommandLine();
	csCommandLine.Delete(0, csCommandLine.Find('-') + 1);
	csCommandLine.Trim();

	if (csCommandLine.CompareNoCase(_T("AUTO")) == 0)
	{
		AddLogEntry(_T("*******Start Auto Live Update*******"));
		m_bAutoUpdate = true;
	}

	else if (csCommandLine.CompareNoCase(_T("AUTOPRODUCTPATCH")) == 0)
	{
		AddLogEntry(_T("*******Start Auto Product Patch Live Update*******"));
		m_bAutoUpdate = true;
		m_bProductPatch = true;
	}

	else if (csCommandLine.CompareNoCase(_T("AUTODATABASEPATCH")) == 0)
	{
		AddLogEntry(_T("*******Start Auto Database Patch Live Update*******"));
		m_bAutoUpdate = true;
		m_bDatabasePatch = true;
	}

	else if (csCommandLine.CompareNoCase(_T("DATABASEPATCH")) == 0)
	{
		AddLogEntry(_T("*******Start Database Patch Live Update*******"));
		m_bDatabasePatch = true;
	}

	DWORD dwDBPatch1 = 0;
	DWORD dwDBPatch2 = 0;
	DWORD dwProductPatch = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("DATABASEPATCH"), dwDBPatch1, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AUTODATABASEPATCH"), dwDBPatch2, HKEY_LOCAL_MACHINE);

	if (dwDBPatch1 || dwDBPatch2)
	{
		AddLogEntry(_T("*******Start Database Patch Live Update*******"));
		m_bDatabasePatch = true;
	}

	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoProductPatch"), dwProductPatch, HKEY_LOCAL_MACHINE);
	if (dwProductPatch == 1)
	{
		m_bProductPatch = true;
	}

	return bRet;
}
bool CLiveUpdateDLL::InstallSetup(CString csFilePath, CString csMD5)
{
	bool bRet = false;	

	TCHAR szMD5[MAX_PATH]={0};
	CCommonFileIntegrityCheck objCreateSignature(_T(""));
	objCreateSignature.GetSignature(csFilePath.GetBuffer(1000), szMD5);
	csFilePath.ReleaseBuffer();
	if(csMD5.CompareNoCase(szMD5)== 0)
	{
		bRet = true;
		CExecuteProcess objExecProcess;
		objExecProcess.ExecuteCommand(csFilePath, _T("\"") + csFilePath + _T("\" /VERYSILENT /NORESTART"));
	}
	else
	{
		bRet = true;
	}
	return bRet;
}