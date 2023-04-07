#include "pch.h"
#include "LiveUpdate.h"
#include "LiveUpdateDLL.h"
#include "CommonFunctions.h"
#include "UpdateManagerEx.h"
#include "FileOperation.h"
#include "CPUInfo.h"
#include "ExecuteProcess.h"
#include "EnumProcess.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "verinfo.h"
//#include "MaxCloudDataMgr.h"
UINT StartLiveUpdate(LPVOID pParam);
UINT PerformLiveUpdate(LPVOID pParam);



CLiveUpdate::CLiveUpdate(void)
{
	m_pThreadUpdateNow = NULL;
	m_bExitApplication = false;
	m_pSendSDKMessageToUI = NULL;
	m_bUpdateCheck = false;
	m_pDownloadMgr = NULL;
	m_hUpdateStatusMutex = NULL;
}



CLiveUpdate::~CLiveUpdate(void)
{
	if(m_pDownloadMgr)
	{
		delete m_pDownloadMgr;
		m_pDownloadMgr = NULL;
	}
	
}

int CLiveUpdate::Update(SENDSDKLVMESSAGEUI pSendMessageToUI, /*LPVOID *pParam*/int iUpdateOption)
{
	//m_pUpdateInfo = (UPDATE_OPTIONS *) pParam;
	memset(&m_objUpdateInfo, 0, sizeof(UPDATE_OPTIONS));
	m_pSendSDKMessageToUI = pSendMessageToUI;
	m_objUpdateInfo.Internet = iUpdateOption;
	int iRet = 0;
	
	HANDLE hUpdateStatusCheckMutex = NULL;
	hUpdateStatusCheckMutex = ::OpenMutex(SYNCHRONIZE, FALSE, _T("Global\\AuUpdateStatusMutex"));
	if (NULL != hUpdateStatusCheckMutex)
	{
		OutputDebugString(L"Update Present");
		CloseHandle(hUpdateStatusCheckMutex);
		hUpdateStatusCheckMutex = NULL;
		iRet = 2;
		return iRet;
	}
	else
	{
		DWORD dwErr = GetLastError();
		if (dwErr == 5)
		{
			OutputDebugString(L"Update Present");
			iRet = 2;
			return iRet;
		}
	}
	if (NULL == m_hUpdateStatusMutex)
	{
		OutputDebugString(L"Update Start");
		m_hUpdateStatusMutex = ::CreateMutex(NULL, FALSE, _T("Global\\AuUpdateStatusMutex"));
	}

	bool bRet = theApp.InitLiveUpdate();
	if(bRet)
	{
		iRet = 1;
		if (!m_bLiveUpdateThread)
		{
			m_pThreadUpdateNow = AfxBeginThread(StartLiveUpdate, this);
			if (m_objUpdateInfo.Internet == 2)
			{
				WaitForSingleObject(m_pThreadUpdateNow->m_hThread,INFINITE);
			}
		}
	}
	return iRet;
}
bool CLiveUpdate::StopLiveUpdate()
{
	CopyFile(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_FILE_NAME, theApp.m_csWaitingForMergePath + L"\\" + INI_FILE_NAME, FALSE);
	CopyFile(CSystemInfo::m_strTempLiveupdate + L"\\" +INI_DELTASERVER_FILE_NAME, theApp.m_csWaitingForMergePath + L"\\" +INI_DELTASERVER_FILE_NAME, FALSE);
	
	theApp.m_bExitThread = true;
	//m_objLiveUpdateEx.IsThreadRunningTest = true;
	if(m_pDownloadMgr)
	{
		delete m_pDownloadMgr;
		m_pDownloadMgr = NULL;
	}
	DWORD dwErrorMe = 0;
	CFileOperation objFileOperation;
	//objFileOperation.DeleteFolderTree(CSystemInfo::m_strTempLiveupdate, true, false,dwErrorMe, _T(""), _T("DownloadTempFiles"));
	Sleep(2000);
	objFileOperation.DeleteFolderTree(CSystemInfo::m_strTempLiveupdate, true, false, dwErrorMe, _T(""), _T(""));
	if(m_pThreadUpdateNow && m_pThreadUpdateNow->m_hThread)
	{
		if(m_bLiveUpdateThread)
		{
			::TerminateThread(m_pThreadUpdateNow->m_hThread,0);
			m_bLiveUpdateThread = false;
			
			::CloseHandle(m_pThreadUpdateNow->m_hThread);
			m_pThreadUpdateNow = NULL;
			//Multiple Time Start Stop Handling
		}
		
	}
	if (NULL != m_hUpdateStatusMutex)
	{
		OutputDebugString(L"Stop Update");
		CloseHandle(m_hUpdateStatusMutex);
		m_hUpdateStatusMutex = NULL;
	}
	return true;
}
UINT StartLiveUpdate(LPVOID pParam)
{
	bool bException = false;
	CLiveUpdate *pLiveUpdate = (CLiveUpdate *)pParam;

	if(!pLiveUpdate)
	{
		return 0;
	}

	pLiveUpdate->m_bLiveUpdateThread = true;

	__try
	{
		PerformLiveUpdate(pParam);
	}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		bException = true;
	}

	pLiveUpdate->m_bLiveUpdateThread = false;
	return 1;
}

UINT PerformLiveUpdate(LPVOID pParam)
{
	ASSERT(pParam);
	CLiveUpdate* pLiveUpdate = (CLiveUpdate*)pParam;
	if (!pLiveUpdate)
	{
		return 1;
	}

	bool bRet = false;

	bRet = pLiveUpdate->UpdateNow();

	CRegistry objReg;
	DWORD dw;
	dw = 1;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsUpdating"), dw, HKEY_LOCAL_MACHINE);


	DWORD dwErrorMe = 0;
	CFileOperation objFileOperation;
	objFileOperation.DeleteFolderTree(CSystemInfo::m_strTempLiveupdate, true, true, dwErrorMe, _T(""), _T("DownloadTempFiles"));

	if (bRet)
	{
		//Set Last Live Update Time
		COleDateTime objOleDateTime = objOleDateTime.GetCurrentTime();
		CString csDate;
		CCPUInfo objCPUInfo;
		csDate.Format(L"%d-%d-%d", objOleDateTime.GetMonth(), objOleDateTime.GetDay(), objOleDateTime.GetYear());
		objReg.Set(CSystemInfo::m_csProductRegKey, L"LastLiveUpdate", csDate, HKEY_LOCAL_MACHINE);

		ULONG64 ulCurTime;
		_time64((__time64_t*)&ulCurTime);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("LU_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
		
	}
	
	memset(&theApp.m_objUpdateStatus, 0, sizeof(UPDATE_STATUS));
	theApp.m_objUpdateStatus.iSuccessErr = UpdateMessages::FINISH_UPDATE;;
	
	if (pLiveUpdate->m_pSendSDKMessageToUI != NULL)
	{
		pLiveUpdate->m_pSendSDKMessageToUI(theApp.m_objUpdateStatus);
	}
	if (NULL != pLiveUpdate->m_hUpdateStatusMutex)
	{
		OutputDebugString(L"Closed Update");
		CloseHandle(pLiveUpdate->m_hUpdateStatusMutex);
		pLiveUpdate->m_hUpdateStatusMutex = NULL;
	}
	
	return 0;
}

bool CLiveUpdate::UpdateNow()
{
	bool bRet = false;
	BOOL bRestartPC = FALSE;
	//Avinash
	int iID=0;
	CString csFailedToUpdate, csExclamation, csStringToDisPlay=_T("");

	CString csAvliveUpdate;
	csAvliveUpdate = CSystemInfo::m_strAppPath[0];
	csAvliveUpdate += _T(":\\AuLiveUpdate\\");
	CreateDirectory(csAvliveUpdate, NULL);

	if(theApp.m_bStandaloneDownload)
	{
		theApp.ReadAllSectionNameFromIniX64();
		theApp.ReadAllSectionNameFromIni();
	}
	else
	{	
#ifdef WIN64
	theApp.ReadAllSectionNameFromIniX64();
#else
	theApp.ReadAllSectionNameFromIni();
#endif
	}
	
	m_pDownloadMgr = new DownloadManagerSDK;
	m_pDownloadMgr->SetCtrlItemsSDK(&m_Status, &m_TotalTimeRemaining, &m_TotalPercentage);
	m_pDownloadMgr->SetSDKParams( m_pSendSDKMessageToUI);
	CCPUInfo objCPUInfo;
	DWORD dwMajorVer = objCPUInfo.GetMajorOSVersion();
	
	bRet = m_pDownloadMgr->DownLoad(m_bExitApplication);

	if(bRet)
	{
		if(theApp.m_iIsUIProduct == 0)
		{
			CUpdateManagerEx objUpdMgr;
			objUpdMgr.SetSDKParams();
			objUpdMgr.ExtractAndUpdateDownloads();
		}
		else
		{
			CString csBackupFolder;
			csBackupFolder = CSystemInfo::m_strAppPath[0];
			csBackupFolder += _T(":\\AuLiveUpdate\\");
		
			CopyFile(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_FILE_NAME, theApp.m_csWaitingForMergePath + L"\\" + INI_FILE_NAME, FALSE);
			int iError = GetLastError();
			CopyFile(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_DELTASERVER_FILE_NAME, theApp.m_csWaitingForMergePath + L"\\" + INI_DELTASERVER_FILE_NAME, FALSE);			
			int iErrorDelta = GetLastError();			
			if(iError == 6)
			{
				Sleep(5000);
				CFile oFileSrc(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_FILE_NAME, CFile::modeRead);
				CFile oFileDst(theApp.m_csWaitingForMergePath + L"\\" + INI_FILE_NAME, CFile::modeWrite | CFile::modeCreate);
				
				UINT iCount = 1024;
				char *pszBuffer = NULL;
				pszBuffer = (char *)calloc(1024, sizeof(char));
				if(pszBuffer != NULL)
				{
					//AddLogEntry (_T("Going to write the file."));
					while((iCount = oFileSrc.Read(pszBuffer, iCount)) > 0)
					{								
						oFileDst.Write(pszBuffer, iCount);									
						memset(pszBuffer, 0x00, 1024 * sizeof(char));
					}
				}

				if(pszBuffer != NULL)
				{
					delete pszBuffer;
					pszBuffer = NULL;
				}
				oFileSrc.Close();
				oFileDst.Close();				
			}
			if(iError == 6)
			{
				Sleep(5000);
				CFile oFileSrc(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_DELTASERVER_FILE_NAME, CFile::modeRead);
				CFile oFileDst(theApp.m_csWaitingForMergePath + L"\\" + INI_DELTASERVER_FILE_NAME, CFile::modeWrite | CFile::modeCreate);
				
				UINT iCount = 1024;
				char *pszBuffer = NULL;
				pszBuffer = (char *)calloc(1024, sizeof(char)); 
				if(pszBuffer != NULL)
				{
					//AddLogEntry (_T("Going to write the file."));
					while((iCount = oFileSrc.Read(pszBuffer, iCount)) > 0)
					{								
						oFileDst.Write(pszBuffer, iCount);									
						memset(pszBuffer, 0x00, 1024 * sizeof(char));
					}
				}

				if(pszBuffer != NULL)
				{
					delete pszBuffer;
					pszBuffer = NULL;
				}
				
				oFileSrc.Close();
				oFileDst.Close();				
			}

			DWORD dwErrorMe = 0;
			CFileOperation objFileOperation;
			CString csFolderPath = CSystemInfo::m_strTempLiveupdate + _T("\\DownloadTempFiles\\*.*");
			objFileOperation.DeleteFolderTree(csFolderPath, true, false, dwErrorMe);
			
		}
	}
	else
	{
		CopyFile(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_FILE_NAME, theApp.m_csWaitingForMergePath + L"\\" + INI_FILE_NAME, FALSE);			
		CopyFile(CSystemInfo::m_strTempLiveupdate + L"\\" + INI_DELTASERVER_FILE_NAME, theApp.m_csWaitingForMergePath + L"\\" + INI_DELTASERVER_FILE_NAME, FALSE);			
	}
	if(m_pDownloadMgr)
	{
		delete m_pDownloadMgr;
		m_pDownloadMgr = NULL;
	}

	if (bRet || m_bExitApplication)
	{
		//AddLogEntry(_T("Pavan : Sleeping for 5 secs...."));
		//Sleep(5000);
		m_bExitApplication = true;
	}

	return bRet;
}

TCHAR* CLiveUpdate::GetModuleFilePath()
{
	TCHAR *szModulePath = new TCHAR[MAX_PATH];
	DWORD dwSize = MAX_PATH;
	int iErrorCode = GetModuleFileName(NULL,szModulePath,dwSize);
	if(iErrorCode == ERROR_INSUFFICIENT_BUFFER)
	{
		delete szModulePath;
		szModulePath = new TCHAR[dwSize];
		GetModuleFileName(NULL,szModulePath,dwSize);
	}
	CString csModulePath(szModulePath);
	csModulePath = csModulePath.Left(csModulePath.ReverseFind(L'\\'));
	_stprintf_s(szModulePath,dwSize,csModulePath);
	return szModulePath;
}


bool CLiveUpdate::Check4ValidDataBackUP(LPCTSTR	pszBackUPFolPath)
{
	bool	bReturn = false;

	if(PathFileExists(pszBackUPFolPath) == FALSE)
	{
		return bReturn;
	}

	int			iCount = 0x00;
	bool		bFound = false;
	CString		cszFolPath;
	CFileFind	objFileFinder;
	
	cszFolPath.Format(L"%s\\*.*",pszBackUPFolPath);

	bFound = objFileFinder.FindFile(cszFolPath);
	while(bFound)
	{
		bFound = objFileFinder.FindNextFileW();
		if (objFileFinder.IsDirectory() == FALSE && objFileFinder.IsDots() == FALSE)
		{
			iCount++;
		}
	}

	objFileFinder.Close();
	if(theApp.m_iUseCloudScanning == 1)
	{
		if(iCount > 32)
			bReturn = true;
	}
	else
	{
		if(iCount > 65)
			bReturn = true;
	}
	return bReturn;
}

bool CLiveUpdate::ExecutePatch(const CString &csPatchFileName, CString csOrgFileName, bool bWaitForUIToClose)
{
	CSystemInfo			objInfo;
	CExecuteProcess		objExecutor;
	
	
	CString csFileToDelete;
	CString csLocalBackUpFolder;
	csLocalBackUpFolder = objInfo.m_strAppPath[0];
	csLocalBackUpFolder += _T(":\\AuLiveUpdate\\");	
	CString csBackupFileName = csLocalBackUpFolder + csPatchFileName;


	if(bWaitForUIToClose)
	{
		if(!IsReadyToInstall())
		{
			AddLogEntry(_T("Not ready to install skipping: %s"), csPatchFileName, 0, true, LOG_WARNING);
			return false;
		}
	}

	csFileToDelete = csLocalBackUpFolder + csOrgFileName;
	DeleteFile(csFileToDelete);

	AddLogEntry(_T(">>>>> Executed Patch: %s"), csBackupFileName, 0, true);
	if(objExecutor.ExecuteCommandWithWait(csBackupFileName, _T("\"") + csBackupFileName + _T("\" /VERYSILENT /NORESTART")))
	{
		AddLogEntry(_T(">>>>> Successfully Executed Patch: %s"), csBackupFileName, 0, true, LOG_WARNING);
		return true;
	}
	else
	{
		AddLogEntry(_T(">>>>> Failed To Execute Patch: %s"), csBackupFileName, 0, true, LOG_WARNING);
		return false;
	}
	
}
bool CLiveUpdate::IsReadyToInstall()
{
	bool bRetVal = false;
	CEnumProcess objEnumProcess;
	if(objEnumProcess.IsProcessRunning(MAX_SCANNER, false, false, false))
	{
		if(!objEnumProcess.IsProcessRunning(MAX_SCANNER, true, false))
		{
			bRetVal = false;
		}
		else
		{
			bRetVal = true;
		}
	}
	else
	{
		bRetVal = true;
	}

	return bRetVal;
}
void CLiveUpdate::ExecuteDeltaRollBack()
{

		

}

bool CLiveUpdate::PostMessageToProtection(UINT WM_Message, UINT ActMon_Message, UINT uStatus)
{
	bool bReply = true;
	//AM_MESSAGE_DATA amMsgData={0};
	//amMsgData.dwMsgType = WM_Message;
	//amMsgData.dwProtectionType = ActMon_Message;
	//amMsgData.bProtectionStatus = (BYTE)uStatus;
	//CMaxCommunicator objComm(_NAMED_PIPE_ACTMON_TO_TRAY);
	//if(objComm.SendData(&amMsgData, sizeof(AM_MESSAGE_DATA)))
	//{
	//	if(!objComm.ReadData((LPVOID)&amMsgData, sizeof(AM_MESSAGE_DATA)))
	//	{
	//		return false;
	//	}
	//	//wait broken so read the result.
	//	bReply = (amMsgData.dwMsgType ? true : false); 
	//}
	//if(ActMon_Message == RESTARTPROTECTION)
	//{
	//	CMaxCommunicator objUITOService(_NAMED_PIPE_MNGRSRV_PROCESSES,false);
	//	MAX_PIPE_DATA_REG pipeData;
	//	SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
	//	pipeData.eMessageInfo = Show_AUSuccessDlg;
	//	objUITOService.SendData(&pipeData, sizeof(MAX_PIPE_DATA_REG));
	//}
	return bReply;
}
bool CLiveUpdate::CheckServerVersion()
{
	return false;
	/*CMaxCloudDataMgr objMaxClientDataMgr;
	BOOL bRet = objMaxClientDataMgr.ServerLiveupdateVersionPortal();
	return (bRet ? true : false); */
}