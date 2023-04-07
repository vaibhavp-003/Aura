/*======================================================================================
FILE             : SpyScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 8/1/2009 7:50:42 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "SpyScanner.h"
#include "SDSystemInfo.h"
#include "MaxExceptionFilter.h"
#include "DirectoryManager.h"
#include <direct.h>
#include <shlwapi.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

void WINAPI StartUpScanThread(LPVOID lpThis);

/*--------------------------------------------------------------------------------------
Function       : CSpyScanner::CSpyScanner
In Parameters  : SENDMESSAGETOUI lpSendMessaegToUI, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CSpyScanner::CSpyScanner(SENDMESSAGETOUIMS lpSendMessaegToUI, CMaxScanner *pMaxScanner)
	:m_lpSendMessaegToUI(lpSendMessaegToUI),
	m_pProcessScanner(NULL),
	m_pFileSystemScanner(NULL),
	m_pRegistryScanner(NULL),
	m_pNetworkScanner(NULL),
	m_bSignatureScan(false),
	m_bDatabaseScan(false),
	m_bVirusScan(false),
	m_bDeepScan(false),
	m_bScanReferences(false),
	m_bAutoQuarantine(false),
	m_pMaxScanner(pMaxScanner),
	m_pStartupScanner(NULL),
	m_bUSBScan(false),
	m_bMachineLearning(false),
	m_bMachineLearningQ(false)
{
	m_csScanDetectedIni=_T("");
	m_dwTempCount = 0;
}

/*--------------------------------------------------------------------------------------
Function       : CSpyScanner::~CSpyScanner
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CSpyScanner::~CSpyScanner()
{

}

void WINAPI StartUpScanThread(LPVOID lpThis)
{
	CSpyScanner	*pThis = (CSpyScanner	*)lpThis;
	pThis->StartStartUPScan();
}

void CSpyScanner::StartStartUPScan()
{
	m_pStartupScanner = new CStartupScanner;
	m_pStartupScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
	m_pStartupScanner->ScanStartupFiles(m_bDeepScan);

	delete m_pStartupScanner;
	m_pStartupScanner = NULL;
}

void WINAPI UpdateUIStatusThread(LPVOID lpThis)
{
	CSpyScanner* pThis = (CSpyScanner*)lpThis;
	pThis->UpdateUIStatus();
}

void CSpyScanner::UpdateUIStatus()
{
	int iSleep = 10000;
	//int iSleep = 2000;
	int iMinitCnt = 0x00;
	int i4Cnt = 0;
	
	//SendScanStatusToUI(Status_Bar_File_Report, 0, 0, csFileName, csPercentage, 0, 0, 0, 0, 0, 0);
	//m_lpSendMessaegToUI(Starting_Startup_Scanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	
	
	

	while (1)
	{
		TCHAR	szData2Show[MAX_PATH] = { 0x00 };
		TCHAR	szBaseString[MAX_PATH] = { 0x00 };
		TCHAR	szPercentage[MAX_PATH] = { 0x00 };

		Sleep(iSleep);

		memset(&szBaseString[0x00], 0x00, MAX_PATH * sizeof(TCHAR));

		if (iMinitCnt >= 12)
		{
			_stprintf_s(szPercentage, MAX_PATH, L"96");
			i4Cnt++;
			switch (i4Cnt)
			{
			case 1:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating Services");
				break;
			case 2:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning Services");
				break;
			case 3:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating Services Entries");
				break;
			case 4:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning Services Entries");
				break;

			case 5:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for Run entries");
				break;
			case 6:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for Run entries");
				break;

			case 7:
				_stprintf_s(szPercentage, MAX_PATH, L"97");
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating User Init");
				break;

			case 8:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning User Init");
				break;

			case 9:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating User Init registry entries");
				break;

			case 10:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning User Init registry entries");
				break;

			case 11:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating shell entries");
				break;
			case 12:
				_tcscpy_s(szBaseString, MAX_PATH, L"Looking for malicious shell entries");
				break;

			case 13:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating BHO's");
				break;

			case 14:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning BHO's ");
				break;

			case 15:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating BHO's entries");
				break;

			case 16:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning BHO's entries");
				break;

			case 17:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating App Init");
				break;

			case 18:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning App Init");
				break;

			case 19:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating App Init entries");
				break;

			case 20:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning App Init entries");
				break;

			case 21:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for Toolbar's");
				break;
			case 22:
				_tcscpy_s(szBaseString, MAX_PATH, L"Searching for Toolbar's");
				break;

			case 23:
				_stprintf_s(szPercentage, MAX_PATH, L"98");
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for Toolbar's entries");
				break;
			case 24:
				_tcscpy_s(szBaseString, MAX_PATH, L"Searching for Toolbar's entries");
				break;

			case 25:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for ActiveX");
				break;

			case 26:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for ActiveX");
				break;

			case 27:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for ActiveX entries");
				break;

			case 28:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for ActiveX entries");
				break;

			case 29:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for Uninstall entries");
				break;

			case 30:
				_tcscpy_s(szBaseString, MAX_PATH, L"Searching for Uninstall entries");
				break;

			case 31:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating Menu Extensions");
				break;
			case 32:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning Menu Extensions");
				break;
			case 33:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating Menu Extensions entries");
				break;
			case 34:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning Menu Extensions entries");
				break;

			case 35:
			{
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for malware in memory");
				iSleep = 2000;
			}
				break;

			case 36:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for malware in memory .");
				break;

			case 37:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for malware in memory . .");
				break;

			case 38:
			{
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for malware in memory . . .");
				i4Cnt = 34;
			}
				break;
			

			default:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning for malware in memory . . .");
				break;
			}
			
				

		}
		else
		{
			_stprintf_s(szPercentage, MAX_PATH, L"93");
			i4Cnt++;
			switch (i4Cnt)
			{
			case 1:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating running Processes");
				break;

			case 2:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning running Processes");
				break;

			case 3:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating for Virus threads");
				break;

			case 4:
				_tcscpy_s(szBaseString, MAX_PATH, L"Checking Virus threads");
				break;

			case 5:
				_stprintf_s(szPercentage, MAX_PATH, L"94");
				_tcscpy_s(szBaseString, MAX_PATH, L"Checking suspicious processes and threads");
				break;

			case 6:
				_tcscpy_s(szBaseString, MAX_PATH, L"Checking for Process injection");
				break;
			case 7:
				_tcscpy_s(szBaseString, MAX_PATH, L"Seaching Registry References");
				break;
			case 8:
				_stprintf_s(szPercentage, MAX_PATH, L"95");
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning Registry References");
				break;
			case 9:
				_tcscpy_s(szBaseString, MAX_PATH, L"Enumerating Startup Entries");
				break;
			case 10:
				_tcscpy_s(szBaseString, MAX_PATH, L"Scanning Startup Entries");
				break;

			case 11:
				_tcscpy_s(szBaseString, MAX_PATH, L"Finding DLL Injection");
				break;

			case 12:
				_tcscpy_s(szBaseString, MAX_PATH, L"Checking API hooks");
				break;

			}

		}

		memset(&szData2Show[0x00], 0x00, MAX_PATH * sizeof(TCHAR));
		_stprintf_s(szData2Show, MAX_PATH, L"%s", szBaseString);
		

		m_lpSendMessaegToUI(Status_Bar_File_Report, eStatus_Detected, 0, 0, szData2Show, szPercentage, 0, 0, 0, 0, 0, 0, 0);
		iMinitCnt++;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSpyScanner::StartScanning
In Parameters  : const TCHAR *strDrivesToScan, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CSpyScanner::StartScanning(const TCHAR *strDrivesToScan)
{
	DWORD dwStartTime = GetTickCount();
	HANDLE		hUpdateUIThraed = NULL;
	//HANDLE		hStartUPThraed = NULL;

	m_bStopScanning = false;
	m_bMachineLearningQ = false;
	m_bMachineLearning = false;
	if(m_pMaxScanner->m_bMachineLearningQ)
	{
		m_bMachineLearningQ = true;
	}
	else if(m_pMaxScanner->m_bMachineLearning)
	{
		m_bMachineLearning = true;;
	}
	/*
	if(m_bDatabaseScan)
	{
		if(!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ)) //Tushar ==> 2 Skip Memory Scan at USB Scan
		{
			if (m_lpSendMessaegToUI)
			{
				m_lpSendMessaegToUI(Starting_Process_Scanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
			}
			m_pProcessScanner = new CProcessScanner;
			m_pProcessScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pProcessScanner->ScanProcesses(m_bDeepScan);

			CString csPercentage;
			csPercentage.Format(L"%d", 4);
			if(m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0,0);

			delete m_pProcessScanner;
			m_pProcessScanner = NULL;
		}

		if(!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ))
		{
			////For Threading
			//CString csPercentage;
			//csPercentage.Format(L"%d", 6);
			//if(m_lpSendMessaegToUI)
			//	m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);
			//
			//hStartUPThraed = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)StartUpScanThread,this,0,0);
			//Sleep(2000);

			if (m_lpSendMessaegToUI)
			{
				hUpdateUIThraed = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UpdateUIStatusThread, this, 0, 0);
			}
			
			m_pStartupScanner = new CStartupScanner;
			m_pStartupScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pStartupScanner->ScanStartupFiles(m_bDeepScan); 
			CString csPercentage;
			csPercentage.Format(L"%d", 6);
			if(m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0,0,0);

			if (hUpdateUIThraed != NULL)
			{
				TerminateThread(hUpdateUIThraed,0x00);
				hUpdateUIThraed = NULL;
			}

			delete m_pStartupScanner;
			m_pStartupScanner = NULL;
		}
		if(!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ))
		{
			m_pNetworkScanner = new CNetworkScanner;
			m_pNetworkScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pNetworkScanner->ScanNetworkConnectionSEH();
			CString csPercentage;
			csPercentage.Format(L"%d", 8);
			if(m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0,0);

			delete m_pNetworkScanner;
			m_pNetworkScanner = NULL;
		}
	}
	*/
	if(m_bDatabaseScan && (!m_bUSBScan  || m_bMachineLearningQ))	// Scan temp only once
	{
		DWORD dwCleanTemp, dwCleanTempIE  = 0;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("CleanTemp"), dwCleanTemp, HKEY_LOCAL_MACHINE);
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("CleanTempIE"), dwCleanTempIE, HKEY_LOCAL_MACHINE);

		//if(m_bAutoQuarantine && !m_bStopScanning && dwCleanTemp)
		if(!m_bStopScanning && dwCleanTemp)
		{
			AddLogEntry(L"Starting Temp File Cleaup!");
			CString csTempPath;
			m_dwTempCount =0;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), csTempPath, HKEY_LOCAL_MACHINE);
			if((csTempPath.GetLength() != 0) && (csTempPath.Find(L":") != -1))
			{
				csTempPath += _T("*.*");
				//AddLogEntry(L"Cleanup: %s", csTempPath);
				DeleteTempFilesSEH(csTempPath,TRUE);
			}
			WCHAR szBuff[1024] = {0};
			GetTempPath(1024, szBuff);
			csTempPath = szBuff;
			if((csTempPath.GetLength() != 0) && (csTempPath.Find(L":") != -1))
			{
				csTempPath += _T("*.*");
				//AddLogEntry(L"Cleanup: %s", csTempPath);
				DeleteTempFilesSEH(csTempPath, TRUE);		
			}
			StartUpdateCount(L"TempCount",m_dwTempCount);
						
			AddLogEntry(L"Finished Temp File Cleaup!");
		}

		if(dwCleanTempIE)
		{
			AddLogEntry(L"Starting Internet Temp File Cleaup!");
			DeleteTempInternetFilesSEH();
			AddLogEntry(L"Finished Internet Temp File Cleaup!");
		}
	}
	
	if((!m_bScanReferences && !m_bMachineLearningQ)  || (m_bDatabaseScan && m_bMachineLearningQ))	// AutoRun.ini Scan
	{
		AddLogEntry(L"Starting Autorun INF Files check!");
		ReportAutoRunInfFiles();
		AddLogEntry(L"Finished Autorun INF Files check!");
	}

	/*
	if (hStartUPThraed != NULL)
	{
		WaitForSingleObject(hStartUPThraed,-1);
		AddLogEntry(L"Start-UP-Entry Wait is Over!");
		hStartUPThraed = NULL;
	}
	*/
	
	if((m_bDatabaseScan || m_bScanReferences))
	{
		if(!m_bStopScanning)
		{
			m_pFileSystemScanner = new CFileSystemScanner;
			m_pFileSystemScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pFileSystemScanner->ScanSystem(strDrivesToScan, m_bSignatureScan,
												m_pobjFilesList, m_pobjFoldersList,
												m_bScanReferences, m_bVirusScan, m_bUSBScan, m_bMachineLearningQ);

			delete m_pFileSystemScanner;
			m_pFileSystemScanner = NULL;
		}
	}

	if((m_bScanReferences))
	{
		if(!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ))
		{
			m_pRegistryScanner = new CRegistryScanner;
			m_pRegistryScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			CString csPercentage;
			csPercentage.Format(L"%d", 93);//98
			if(m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0, 0);

			//m_pRegistryScanner->ScanRegistry(m_pobjFilesList, m_pobjFoldersList, m_bScanReferences);
			delete m_pRegistryScanner;
			m_pRegistryScanner = NULL;
		}

		if(m_bAutoQuarantine && !m_bStopScanning)
		{
			m_pFileSystemScanner = new CFileSystemScanner;
			m_pFileSystemScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			CString csDrives(strDrivesToScan);
			CString csToken;
			int iPos = 0;
			csToken = csDrives.Tokenize(L"|", iPos);
			while(csToken.GetLength() > 0)
			{
				//Clean Files (*.exe, *.dll. *.sys) From System Volume information then sending to scan
				m_csFolderPath.Format(L"%s\\%s", csToken, _T("system volume information"));
				CleanSysVolumeInfoFolderWithSEH();

				m_pFileSystemScanner->ScanSystemWithSignatureSEH(csToken + _T("\\system volume information"), m_bVirusScan, m_bDeepScan, m_bDatabaseScan);
				csToken = csDrives.Tokenize(L"|", iPos);
			}
			delete m_pFileSystemScanner;
			m_pFileSystemScanner = NULL;
		}
	}

	if(m_bSignatureScan || m_bMachineLearning)
	{
		if(!m_bStopScanning)
		{
			m_pFileSystemScanner = new CFileSystemScanner;
			m_pFileSystemScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pFileSystemScanner->ScanSystemWithSignatureSEH(strDrivesToScan, m_bVirusScan, m_bDeepScan, m_bDatabaseScan, m_bUSBScan);
			delete m_pFileSystemScanner;
			m_pFileSystemScanner = NULL;
		}
	}

	if(m_bRegFixScan || m_bRegFixForOptionTab)
	{
		if(!m_bStopScanning && (!m_bUSBScan  || m_bMachineLearningQ))
		{
			m_pRegistryScanner = new CRegistryScanner;
			m_pRegistryScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			//m_pRegistryScanner->ScanRegFixEntry(m_bRegFixForOptionTab);
			CString csPercentage;
			csPercentage.Format(L"%d", 91);//96
			if(m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0, 0);

			delete m_pRegistryScanner;
			m_pRegistryScanner = NULL;
		}
	}

	if (m_bDatabaseScan)
	{
		if (!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ)) //Tushar ==> 2 Skip Memory Scan at USB Scan
		{
			if (m_lpSendMessaegToUI)
			{
				m_lpSendMessaegToUI(Starting_Process_Scanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
			}
			if (m_lpSendMessaegToUI)
			{
				hUpdateUIThraed = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UpdateUIStatusThread, this, 0, 0);
			}

			m_pProcessScanner = new CProcessScanner;
			m_pProcessScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pProcessScanner->ScanProcesses(m_bDeepScan);


			CString csPercentage;
			csPercentage.Format(L"%d", 4);
			if (m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report, eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0, 0);

			

			delete m_pProcessScanner;
			m_pProcessScanner = NULL;
		}

		if (!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ))
		{
			////For Threading
			//CString csPercentage;
			//csPercentage.Format(L"%d", 6);
			//if(m_lpSendMessaegToUI)
			//	m_lpSendMessaegToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);
			//
			//hStartUPThraed = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)StartUpScanThread,this,0,0);
			//Sleep(2000);

			/*if (m_lpSendMessaegToUI)
			{
				hUpdateUIThraed = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UpdateUIStatusThread, this, 0, 0);
			}*/

			m_pStartupScanner = new CStartupScanner;
			m_pStartupScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pStartupScanner->ScanStartupFiles(m_bDeepScan);
			CString csPercentage;
			csPercentage.Format(L"%d", 6);
			if (m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report, eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0, 0);

			if (hUpdateUIThraed != NULL)
			{
				TerminateThread(hUpdateUIThraed, 0x00);
				hUpdateUIThraed = NULL;
			}

			delete m_pStartupScanner;
			m_pStartupScanner = NULL;
		}
		if (!m_bStopScanning && (!m_bUSBScan || m_bMachineLearningQ))
		{
			m_pNetworkScanner = new CNetworkScanner;
			m_pNetworkScanner->SetReporter(m_lpSendMessaegToUI, m_pMaxScanner);
			m_pNetworkScanner->ScanNetworkConnectionSEH();
			CString csPercentage;
			csPercentage.Format(L"%d", 8);
			if (m_lpSendMessaegToUI)
				m_lpSendMessaegToUI(Status_Bar_File_Report, eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0, 0);

			delete m_pNetworkScanner;
			m_pNetworkScanner = NULL;
		}
	}
	CTimeSpan ctTimeSpan = ((GetTickCount() - dwStartTime)/1000);
	CString csMessage;
	csMessage.Format(L"Time taken: Hours: %02d, Minutes: %02d, Seconds: %02d\n", (DWORD)ctTimeSpan.GetHours(), (DWORD)ctTimeSpan.GetMinutes(), (DWORD)ctTimeSpan.GetSeconds());
	AddLogEntry(csMessage);
	//OutputDebugString(csMessage);
}

/*--------------------------------------------------------------------------------------
Function       : CSpyScanner::StopScanning
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CSpyScanner::StopScanning()
{
	m_bStopScanning = true;

	if(m_pProcessScanner)
		m_pProcessScanner->StopScanning();

	if(m_pFileSystemScanner)
		m_pFileSystemScanner->StopScanning();

	if(m_pRegistryScanner)
		m_pRegistryScanner->StopScanning();

	if(m_pNetworkScanner)
		m_pNetworkScanner->StopScanning();

	if(m_pStartupScanner)
		m_pStartupScanner->StopScanning();
}

BOOL CSpyScanner::DeleteTempFilesSEH(LPCTSTR lpDirectoryName, BOOL bSubDir)
{
	__try
	{
		return DeleteTempFiles(lpDirectoryName, bSubDir);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception Caught in DeleteTempFilesSEH: %s", lpDirectoryName);
	}
	return FALSE;
}

BOOL CSpyScanner::DeleteTempFiles(LPCTSTR lpDirectoryName, BOOL bSubDir)
{
	CFileFind	oFileFind;
	BOOL		bContinue = FALSE;
	CString csFileName;
	if((bContinue = oFileFind.FindFile(lpDirectoryName)) != 0)
	{
		while(bContinue)
		{
			bContinue = oFileFind.FindNextFile();
			if(oFileFind.IsDots())
			{
				continue;
			}
			CString csFile = oFileFind.GetFilePath();
			csFile.MakeLower();
			if(csFile.GetLength() >= MAX_PATH)
			{
				AddLogEntry(L"Skipped Deleting file with long path: %s", csFile);
				continue;
			}
			if(csFile.Find(L":") == -1)
			{
				AddLogEntry(L"Skipped Deleting invalid File Path: %s", csFile);
				continue;
			}
			if(csFile.Find(L"aumainui.exe") != -1)	
			{
				AddLogEntry(L"Skipped Deleting our file File Path: %s", csFile);
				continue;
			}
			if(oFileFind.IsDirectory() && bSubDir)
			{
				WCHAR lpszSubDirPath[ MAX_PATH] = {0};
				wcscpy_s(lpszSubDirPath, MAX_PATH, oFileFind.GetFilePath());
				if(_tcsstr(lpszSubDirPath, _T("smtmp")) != NULL)
					continue;

				wcscat_s(lpszSubDirPath, MAX_PATH, _T("\\*.*"));
				DeleteTempFiles(lpszSubDirPath, TRUE);
			}
			if(oFileFind.IsDirectory())
			{
				csFileName = oFileFind.GetFileName();
				if(csFileName.CompareNoCase(_T("Quarantine")) != 0)
					RemoveDirectory(oFileFind.GetFilePath());	
			}
			else
			{
				CString csFileName = oFileFind.GetFilePath();
				CFileFind filefind;
				BOOL bPresent = filefind.FindFile(csFileName);
				if(!bPresent)
					return FALSE;
				filefind.FindNextFile();

				//Remove Read only attri
				DWORD dwAttrs = GetFileAttributes(csFileName);
				if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
				{
					SetFileAttributes(csFileName, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
				}
				if(csFileName.CompareNoCase(_T("ServerVersionEx.txt")) != 0)
				{
					csFileName.MakeLower();
					if(csFileName.Find(_T("exclude")) == -1)
					{
						CString csTemp;
						csTemp.Format(L"%s%s",_T("Deleting Temp/Temp IE-"),csFileName);
						if(m_lpSendMessaegToUI && csTemp.GetLength() <= MAX_PATH)
						{
							m_lpSendMessaegToUI(Delete_TempFile, eStatus_NotApplicable, 0, 0, csTemp, 0, 0, 0, 0, 0, 0, 0, 0);
						}
						//StartUpdateCount(L"TempCount");
						if(m_bAutoQuarantine)
						{
							DeleteFile(csFileName);
						}
						else
						{
							m_dwTempCount++;
						}
					}
				}
			}
		}
		oFileFind.Close();
	}
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CSpyScanner::StartUpdateCount
In Parameters  : CString csKey,DWORD dwCount, 
Out Parameters : bool 
Description    : 
Author & Date  : 
--------------------------------------------------------------------------------------*/
bool CSpyScanner::StartUpdateCount(CString csKey,DWORD dwCount)
{
	if(m_csScanDetectedIni.IsEmpty())
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),m_csScanDetectedIni,HKEY_LOCAL_MACHINE);
		if(!m_csScanDetectedIni.IsEmpty())
		{
			m_csScanDetectedIni.Format(_T("%sSetting\\wormcounts.ini"),m_csScanDetectedIni);
		}
	}
	/*if(dwCount== 0)
	{
		int iCount = GetPrivateProfileInt(L"SCAN_COUNTS", csKey,0, m_csScanDetectedIni);
		dwCount = iCount+1;
	}*/
	CString csCount;
	csCount.Format(_T("%d"),dwCount);
	WritePrivateProfileStringW(L"SCAN_COUNTS", csKey, csCount, m_csScanDetectedIni);
	return true;
}
/*--------------------------------------------------------------------------------------
Function       : CleanSysVolumeInfoFolderWithSEH
In Parameters  : void
Out Parameters : 
Description    : To Clean system information folder in selected drive with structured exception Handeling.
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CSpyScanner::CleanSysVolumeInfoFolderWithSEH()
{
	__try{
			CleanSysVolumeInfoFolder();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("CleanSysVolumeInfoFolderWithSEH"),false))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : CleanSysVolumeInfoFolder
In Parameters  : void
Out Parameters : 
Description    : To Clean system information folder in selected drive
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CSpyScanner::CleanSysVolumeInfoFolder()
{
	if(m_csFolderPath.Trim().GetLength() > 0)
		EnumFolder(m_csFolderPath);
}

/*--------------------------------------------------------------------------------------
Function       : EnumFolder
In Parameters  : CString csFolderPath
Out Parameters : 
Description    : To Enumerate Given folder
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CSpyScanner::EnumFolder(CString csFolderPath)
{
	CFileFind objFileFind;

	CString csFileFilePath = csFolderPath + _T("\\*.*");
	
	BOOL bFind = objFileFind.FindFile(csFileFilePath);

	if(FALSE == bFind)
	{
		return;
	}

	while(bFind)
	{
		bFind = objFileFind.FindNextFileW();
		if(objFileFind.IsDots())
			continue;
		
		if(objFileFind.IsDirectory())
		{			
			EnumFolder(objFileFind.GetFilePath());
		}
		else
		{
			CString csFileName = objFileFind.GetFilePath();
			csFileName.Trim().MakeLower();
			if( csFileName.Find(L".exe") > 0 ||  csFileName.Find(L".dll") > 0 || csFileName.Find(L".sys") > 0)
			{
				//AddLogEntry(_T("Cleaning : ") + csFileName);
				SetFileAttributes(csFileName, FILE_ATTRIBUTE_NORMAL);
				DeleteFile(csFileName);
			}
		}		
	}
	objFileFind.Close();
}

BOOL CSpyScanner::DeleteTempInternetFilesSEH()
{
	__try
	{
		return DeleteTempInternetFiles();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception Caught in DeleteTempFilesSEH:");
	}
	return FALSE;
}

BOOL CSpyScanner::DeleteTempInternetFiles()
{
	TCHAR szPath[MAX_PATH] = {0};
	CString csValue;
	CDirectoryManager oDirectoryManager;
	CRegistry oRegistry;	//if(SUCCEEDED(SHGetFolderPath(0, CSIDL_INTERNET_CACHE , NULL, 0, szPath)))
	oRegistry.Get(CSystemInfo::m_csProductRegKey, L"TempIEPath", csValue,HKEY_LOCAL_MACHINE);
	oDirectoryManager.MaxDeleteDirectory(csValue, L"Content.IE5", true, false);
	oDirectoryManager.MaxDeleteDirectory(csValue + CString(L"\\Content.IE5"), L"", true, false);
	return TRUE;
}

bool CSpyScanner::ScanFile(LPMAX_PIPE_DATA_REG lpPipeDataReg)
{
	bool bReturnVal = false;
	MAX_SCANNER_INFO oMaxScannerInfo = {0};
	if(lpPipeDataReg->eMessageInfo == SD_ScanFile)				// Auto quarantine OFF
	{
		oMaxScannerInfo.eMessageInfo = File;
		oMaxScannerInfo.eScannerType = Scanner_Type_Max_Email_Scan;
		_tcscpy_s(oMaxScannerInfo.szFileToScan, _countof(oMaxScannerInfo.szFileToScan), lpPipeDataReg->strValue);

		bReturnVal = m_pMaxScanner->ScanFile(&oMaxScannerInfo);

		if(oMaxScannerInfo.ThreatDetected == 1)
		{
			m_lpSendMessaegToUI(File, eStatus_Detected, oMaxScannerInfo.ulThreatID, 0, oMaxScannerInfo.szFileToScan, oMaxScannerInfo.szThreatName, 0, 0, 0, 0, 0, 0, 0);
		}
		else
		{
			m_lpSendMessaegToUI(Status_Bar_File, eStatus_NotApplicable, 0, 0, oMaxScannerInfo.szFileToScan, 0, 0, 0, 0, 0, 0, 0, 0);
		}
	}
	else if(lpPipeDataReg->eMessageInfo == ScanSingleFile)		// Auto quarantine ON
	{
		oMaxScannerInfo.AutoQuarantine = 1;
		oMaxScannerInfo.eMessageInfo = File;
		oMaxScannerInfo.eScannerType = Scanner_Type_Max_Email_Scan;
		_tcscpy_s(oMaxScannerInfo.szFileToScan, _countof(oMaxScannerInfo.szFileToScan), lpPipeDataReg->strValue);
		_tcscpy_s(oMaxScannerInfo.szFreshFile, _countof(oMaxScannerInfo.szFreshFile), lpPipeDataReg->strKey);
		_tcscpy_s(oMaxScannerInfo.szBackupFileName, _countof(oMaxScannerInfo.szBackupFileName), lpPipeDataReg->strBackup);
		
		bReturnVal = m_pMaxScanner->ScanFile(&oMaxScannerInfo);

		if(oMaxScannerInfo.ThreatDetected || oMaxScannerInfo.ThreatSuspicious)
		{
			if(oMaxScannerInfo.ThreatRepaired)
				lpPipeDataReg->eStatus = eStatus_Repaired;
			else if(oMaxScannerInfo.ThreatQuarantined)
				lpPipeDataReg->eStatus = eStatus_Quarantined;
		}
	}
	return bReturnVal;
}

void CSpyScanner::ReportAutoRunInfFiles()
{
	//if(m_lpSendMessaegToUI)
	{
		for(int drive = 1; drive <= 26; drive++)
		{
			if(!_chdrive(drive))
			{
				CString csDrive, csAutoRun;
				csDrive.Format( _T("%c:\\"), (drive + 'A' - 1));
				csAutoRun.Format( _T("%c:\\AutoRun.inf"), (drive + 'A' - 1));
				if(_waccess(csAutoRun, 0) == 0 && !::PathIsDirectory(csAutoRun))
				{
					UINT DriveType = GetDriveType(csDrive);
					if(DriveType == DRIVE_FIXED || DriveType == DRIVE_REMOVABLE)
					{
						AddLogEntry(L"Delete AutoRun.inf: %s", csAutoRun);
						if(::DeleteFile(csAutoRun))
						{
							if(DriveType == DRIVE_REMOVABLE)
							{
								::CreateDirectory(csAutoRun, 0);
								SetFileAttributes(csAutoRun, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
							}
						}
						else
						{
							AddInRestartDeleteList(RD_FILE_DELETE, 8013,
								csAutoRun);
						}
						//m_lpSendMessaegToUI(File, eStatus_Detected, 8013, 0, (LPCTSTR)csAutoRun, 0, 0, 0, 0, 0, 0, 0);
					}
				}
			}
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::AddInRestartDeleteList
In Parameters  : RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue,
Out Parameters : BOOL
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CSpyScanner::AddInRestartDeleteList(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID,
											LPCTSTR szValue)
{
	BOOL bRet = false;

	//Invalid.Registry entries are Registry Scan entries....Restart not required for them.
	if(ulSpyNameID == 2890764)
		return bRet;

	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	WCHAR strCount[50] = {0};
	WCHAR strValue[MAX_PATH*4] = {0};

	WCHAR *szSection[9] = {
							L"File_Delete", L"File_Backup",
							L"Folder", L"RegistryKey",
							L"RegistryValue", L"RegistryData",
							L"File_Rename", L"File_Replace",
							L"Native_Backup"
						};

	LPTSTR lpszSection = NULL;

	if(eRD_Type == RD_FILE_DELETE)
	{
		lpszSection = szSection[0];
	}
	else if(eRD_Type == RD_FILE_BACKUP)
	{
		lpszSection = szSection[1];
	}
	else if(eRD_Type == RD_FOLDER)
	{
		lpszSection = szSection[2];
	}
	else if(eRD_Type == RD_KEY)
	{
		lpszSection = szSection[3];
	}
	else if(eRD_Type == RD_VALUE)
	{
		lpszSection = szSection[4];
	}
	else if(eRD_Type == RD_DATA)
	{
		lpszSection = szSection[5];
	}
	else if(eRD_Type == RD_FILE_RENAME)
	{
		lpszSection = szSection[6];
	}
	else if(eRD_Type == RD_FILE_REPLACE)
	{
		lpszSection = szSection[7];
	}
	else if(eRD_Type == RD_NATIVE_BACKUP)
	{
		lpszSection = szSection[8];
	}

	if(lpszSection == NULL)
	{
		return FALSE;
	}

	CreateWormstoDeleteINI(strINIPath);

	UINT ulWormCnt = GetPrivateProfileIntW(lpszSection, L"WormCnt", 0, strINIPath);
	wsprintf(strCount, L"%d", ++ulWormCnt);
	WritePrivateProfileStringW(lpszSection, L"WormCnt", strCount, strINIPath);

	wsprintf(strValue, L"%ld^%s", ulSpyNameID, szValue);
	WritePrivateProfileStringW(lpszSection, strCount, strValue, strINIPath);
	AddLogEntry(L"^^^^^: %s", szValue);
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::CreateWormstoDeleteINI
In Parameters  : CString strINIPath,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CSpyScanner::CreateWormstoDeleteINI(CString strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
									FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Rename", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Replace", L"WormCnt", L"0", strINIPath);
	}
}
