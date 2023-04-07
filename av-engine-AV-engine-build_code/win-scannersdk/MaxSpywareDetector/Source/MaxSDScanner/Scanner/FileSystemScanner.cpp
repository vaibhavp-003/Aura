/*======================================================================================
FILE             : FileSystemScanner.cpp
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
				  
CREATION DATE    : 8/1/2009 6:55:37 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "..\SDScanner.h"
#include "FileSystemScanner.h"
#include "MaxExceptionFilter.h"
#include "Logger.h"
#include "HardDiskManager.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CFileSystemScanner::CFileSystemScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CFileSystemScanner::CFileSystemScanner(void)
{
	m_dwTotalNoOfFilesToScan = 0;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemScanner::~CFileSystemScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CFileSystemScanner::~CFileSystemScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemScanner::ScanSystem
In Parameters  : const TCHAR *strDrivesToScan, bool bSignatureScan, const CS2U& objFilesList,
					const CS2U& objFoldersList, bool bScanReferences
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemScanner::ScanSystem(const TCHAR *strDrivesToScan, bool bSignatureScan,
									CS2U* pobjFilesList, CS2U* pobjFoldersList,
									bool bScanReferences, bool bVirusScan, bool bUsbScan, bool bMachineLearning)
{
	m_pobjFilesList = pobjFilesList;
	m_pobjFoldersList = pobjFoldersList;
	m_bVirusScan = bVirusScan;
	__try
	{
		if(!m_bStopScanning && (!bScanReferences && (!bUsbScan || bMachineLearning)))
		{
			AddLogEntry(Starting_Cookie_Scanner, L"Cookies Scan");
			SendScanStatusToUI(Starting_Cookie_Scanner);
			StartCookieScan(strDrivesToScan);
			AddLogEntry(Starting_Cookie_Scanner, L"Cookies Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught AuScanner Cookie Scan Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning && !bScanReferences)
		{
			AddLogEntry(Starting_File_Scanner, L"File Scan");
			SendScanStatusToUI(Starting_File_Scanner);
			StartFileScan(strDrivesToScan);
			AddLogEntry(Starting_File_Scanner, L"File Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught AuScanner File Scan Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning && bScanReferences)
		{
			AddLogEntry(Starting_Folder_Scanner, L"Folder Scan");
			SendScanStatusToUI(Starting_Folder_Scanner);
			StartFolderScan(strDrivesToScan);
			AddLogEntry(Starting_Folder_Scanner, L"Folder Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught AuScanner Folder Scan Mode")))
	{
	}
	
	__try
	{
		//Avoid Quick Signature Scan incase full scan is selected!
		if(!m_bStopScanning && !bSignatureScan && !bScanReferences)
		{
			if(!m_bVirusScan)
			{
				AddLogEntry(Starting_Signature_Scanner, L"Signature Scan");
				SendScanStatusToUI(Starting_Signature_Scanner);
			}
			else
			{
				AddLogEntry(Starting_Signature_And_Virus_Scanner, L"Signature And Virus Scan");
				SendScanStatusToUI(Starting_Signature_And_Virus_Scanner);
			}
			PerformQuickSignatureScan();
			if(!bVirusScan)
			{
				AddLogEntry(Starting_Signature_Scanner, L"Signature Scan", 0, 0, 0, 0, false);
			}
			else
			{
				AddLogEntry(Starting_Signature_And_Virus_Scanner, L"Signature And Virus Scan", 0, 0, 0, 0, false);
			}
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught AuScanner Quick File Scan Mode")))
	{
	}
}
///*-------------------------------------------------------------------------------------
//Function		:	CFileSystemScanner::SetParam
//Description		:	To set different parameters for scanner	 
//--------------------------------------------------------------------------------------*/
//void CFileSystemScanner::SetParams(bool bMacLearning)
//{
//	m_pMaxScanner->SetParams(bMacLearning);
//}
/*--------------------------------------------------------------------------------------
Function       : CFileSystemScanner::ScanSystemWithSignatureSEH
In Parameters  : const TCHAR *strDrivesToScan, bool bVirusScan, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemScanner::ScanSystemWithSignatureSEH(const TCHAR *strDrivesToScan, bool bVirusScan, bool bDeepScan, bool bDatabaseScan, bool bUSBScan)
{
	__try
	{
		ScanSystemWithSignature(strDrivesToScan, bVirusScan, bDeepScan, bDatabaseScan, bUSBScan);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught AuScanner Signature Scan Mode")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemScanner::ScanSystemWithSignature
In Parameters  : const TCHAR *strDrivesToScan, bool bVirusScan, bool bDeepScan
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemScanner::ScanSystemWithSignature(const TCHAR *strDrivesToScan, bool bVirusScan, bool bDeepScan, bool bDatabaseScan, bool bUSBScan)
{
	bool bIsSVIScan = false;
	CString csTempDrives(strDrivesToScan);
	if(csTempDrives.Find(L"system volume information") >= 0)
	{
		bIsSVIScan = true;
	}

	if(!bIsSVIScan)
	{
		if(!bVirusScan)
		{
			AddLogEntry(Starting_Signature_Scanner, L"Signature Scan");
			SendScanStatusToUI(Starting_Signature_Scanner);
		}
		else
		{
			AddLogEntry(Starting_Signature_And_Virus_Scanner, L"Signature And Virus Scan");
			SendScanStatusToUI(Starting_Signature_And_Virus_Scanner);
		}
	}

	m_bCustomScan = !bDatabaseScan;
	m_bSendStatusToUI = true;

	m_csIgnoreFolder = CSystemInfo::m_strAppPath + QUARANTINEFOLDER;
	m_csIgnoreFolder.MakeLower();

	int iPos = 0;
	CString csToken(L"");
	CString csDrives = strDrivesToScan;
	csDrives.MakeLower();
	m_csDrivesToScan = csDrives;
	CWinThread *pCountThread = NULL;
	CWinThread *pStatusThread = NULL;
	if(!bIsSVIScan)
	{
		pCountThread = AfxBeginThread(TotalDriveScanningSizeThread, this, THREAD_PRIORITY_HIGHEST, NULL, CREATE_SUSPENDED, NULL);
		pStatusThread = AfxBeginThread(ScanningStatusThread, this, THREAD_PRIORITY_HIGHEST, NULL, CREATE_SUSPENDED, NULL);
		if(pCountThread)
		{
			pCountThread->m_bAutoDelete = FALSE;
			pCountThread->ResumeThread();
		}
		if(pStatusThread)
		{
			pStatusThread->m_bAutoDelete = FALSE;
			pStatusThread->ResumeThread();
		}
	}
	
	csToken = csDrives.Tokenize(L"|", iPos);
	csToken.Trim();

	m_bVirusScan = bVirusScan;
	m_bDeepScan = bDeepScan;
	m_bUSBScan = bUSBScan;
	TCHAR	szDrive[0x5] = {0};
	TCHAR	szDriveBk[0x5] = {0};
	BOOL	bLastScan = FALSE;
	if(theApp.m_bBGScanner)
	{
		bLastScan = CFileSystemBase::GetLastScanStatus(szDriveBk);
	}

	while((!m_bStopScanning) && (csToken.GetLength() != 0))
	{
		AddLogEntry(L"Scanning Drive: %s", csToken);
		szDrive[0x00] = csToken[0x00];
		szDrive[0x01] = csToken[0x01];
		szDrive[0x02] = '\0';
		if(_T('\\') != csToken.GetAt(csToken.GetLength()-1))
		{
			csToken += '\\';
		}
		if(theApp.m_bBGScanner)
		{
			if(bLastScan == TRUE)
			{
				if (_tcsstr(szDriveBk,szDrive) != NULL)
				{
					CFileSystemBase::ScanSystemWithSignature(csToken);
				}
			}
			else
			{
				CFileSystemBase::ScanSystemWithSignature(csToken);
			}			
		}
		else
		{
			CFileSystemBase::ScanSystemWithSignature(csToken);
		}
		csToken = csDrives.Tokenize(L"|", iPos);
		csToken.Trim();
	}
	if(theApp.m_bBGScanner)
	{
		SaveCurStage(L"",0);
	}
	UnloadAllDatabase();

	if(!bIsSVIScan)
	{
		if(!bVirusScan)
		{
			AddLogEntry(Starting_Signature_Scanner, L"Signature Scan", 0, 0, 0, 0, false);
		}
		else
		{
			AddLogEntry(Starting_Signature_And_Virus_Scanner, L"Signature And Virus Scan", 0, 0, 0, 0, false);
		}
	}
	m_bSendStatusToUI = false;
	if(pCountThread)
	{
		WaitForSingleObject(pCountThread->m_hThread, INFINITE);
		delete pCountThread;
		pCountThread = NULL;
	}
	if(pStatusThread)
	{
		WaitForSingleObject(pStatusThread->m_hThread, INFINITE);
		delete pStatusThread;
		pStatusThread = NULL;
	}
}

UINT _cdecl TotalDriveScanningSizeThread(LPVOID pParam)
{
	CFileSystemScanner* pFileSystemScanner = (CFileSystemScanner*)pParam;
	pFileSystemScanner->GetTotalScanningSize();
	return 0;
}

void CFileSystemScanner::GetTotalScanningSize()
{
	int iPos = 0;
	CString csDrives = m_csDrivesToScan;
	CString csToken = csDrives.Tokenize(L"|", iPos);
	csToken.Trim();

	m_dwTotalNoOfFilesToScan = 0;

	//This will be the actual size
	csDrives = m_csDrivesToScan;
	iPos = 0;
	csToken = csDrives.Tokenize(L"|", iPos);
	csToken.Trim();
	while((!m_bStopScanning) && (csToken.GetLength() != 0))
	{
		//AddLogEntry(L"Enumerating Drive: %s", csToken);
		if(_T('\\') != csToken.GetAt(csToken.GetLength()-1))
		{
			csToken += '\\';
		}

		EnumFolder(csToken, false, true, &m_dwTotalNoOfFilesToScan);
		if(theApp.IsAutoCleanActive())
		{
			EnumFolder(csToken + L"system volume information\\", false, true, &m_dwTotalNoOfFilesToScan);
		}
		csToken = csDrives.Tokenize(L"|", iPos);
		csToken.Trim();
	}

	m_bActualValueReady = true;

	csToken.Format(L"Actual Total No of Files To Scan: %d", m_dwTotalNoOfFilesToScan);
	AddLogEntry(csToken);
}
