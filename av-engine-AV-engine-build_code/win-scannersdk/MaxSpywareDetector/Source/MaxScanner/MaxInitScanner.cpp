/*======================================================================================
FILE             : MaxInitScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
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
CREATION DATE    : 8/1/2009 6:39:35 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxInitScanner.h"
#include "MaxDBScanner.h"
#include "OptionHandler.h"
#include "RecoverHandler.h"
#include "PluginHandler.h"
#include "ThreatCommunityHandler.h"
#include "MaxConstant.h"
#include "SDConstants.h"
#include "MaxExceptionFilter.h"
#include "MaxPipes.h"
#include "MaxProtectionMgr.h"

#ifndef _STANDALONE_
#include "MaxScanner.h"
#include "QuarentineHandler.h"
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : MaxInitScanner::MaxInitScanner
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Siddharam Pujari.
--------------------------------------------------------------------------------------*/
CMaxInitScanner::CMaxInitScanner()
{
	m_hGlobalMutex = NULL;
	m_hGlobalMutexML = NULL;
	m_hGlobalMutexBKG = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxInitScanner::~CMaxInitScanner
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Siddharam Pujari.
--------------------------------------------------------------------------------------*/
CMaxInitScanner::~CMaxInitScanner()
{
	if (m_hGlobalMutex != NULL)
	{
		CloseHandle(m_hGlobalMutex);
		m_hGlobalMutex = NULL;
	}

	if(m_hGlobalMutexML != NULL)
	{
		CloseHandle(m_hGlobalMutexML);
		m_hGlobalMutexML = NULL;
	}
	if(m_hGlobalMutexBKG != NULL)
	{
		::ReleaseMutex(m_hGlobalMutexBKG);
		m_hGlobalMutexBKG = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : ScanInThread
In Parameters  : LPVOID lpVoid, 
Out Parameters : UINT 
Description    : 
Author & Date  : Siddharam Pujari.
--------------------------------------------------------------------------------------*/
UINT ScanInThread(LPVOID lpVoid)
{
	__try
	{
		CMaxInitScanner *pThis = (CMaxInitScanner*)lpVoid;
		if(pThis)
		{
			pThis->StartScanner();
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("MaxInitScanner:StartScanner")))
	{
		AddLogEntry(_T("StartScanner MaxInitScanner Exception Filter"));
	}
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxInitScanner::InitScanner
In Parameters  : 
Out Parameters : BOOL 
Description    : 
Author & Date  : Siddharam Pujari.
--------------------------------------------------------------------------------------*/
BOOL CMaxInitScanner::InitScanner()
{
	CMaxExceptionFilter::InitializeExceptionFilter();	
	SecureZeroMemory(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
	SecureZeroMemory(&sMaxPipeDataCmd, sizeof(MAX_PIPE_DATA_CMD));

	WCHAR wcsFileName[MAX_PATH] = {0};
	CString csCmdLineArg = GetCommandLine();
	GetModuleFileName(0, wcsFileName, MAX_PATH);
	csCmdLineArg.Replace(CString(L"\"") + wcsFileName + CString(L"\""), _T(""));
	
	
#ifdef _STANDALONE_	
	csCmdLineArg.MakeLower();
	int iFind = csCmdLineArg.Find(L"cmdscanner.exe");
	if(iFind != -1)
		csCmdLineArg = csCmdLineArg.Mid(iFind+17, csCmdLineArg.GetLength()) ;
    //csCmdLineArg.Replace(_T("/r") , _T(""));
#endif

	csCmdLineArg.Trim();
	if(csCmdLineArg.GetLength() == 0)
	{
		return false;
	}
	csCmdLineArg.MakeUpper();
	CString csToken;
	int iPos = 0;
	csToken = csCmdLineArg.Tokenize(L" ", iPos);
	while(csToken.GetLength() > 0)
	{
		if(_wcsicmp((LPCTSTR)csToken, _T("/U")) == 0)
		{
			sMaxPipeData.sScanOptions.IsUSBScanner = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/S")) == 0)
		{
			sMaxPipeData.sScanOptions.SignatureScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/V")) == 0)
		{
			sMaxPipeData.sScanOptions.VirusScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/R")) == 0)
		{
			sMaxPipeData.sScanOptions.RootkitScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/K")) == 0)
		{
			sMaxPipeData.sScanOptions.KeyLoggerScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/H")) == 0)
		{
			sMaxPipeData.sScanOptions.HeuristicScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/D")) == 0)
		{
			sMaxPipeData.sScanOptions.DBScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/O")) == 0)
		{
			sMaxPipeData.sScanOptions.RegFixOptionScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/X")) == 0)
		{
			sMaxPipeData.sScanOptions.RecoverSpyware = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/C")) == 0)
		{
			sMaxPipeData.sScanOptions.CustomScan = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/Q")) == 0)
		{
			sMaxPipeData.sScanOptions.Quarantine = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/G")) == 0)
		{
			sMaxPipeData.sScanOptions.QuarentineEntries = 1;
		}
		else if(_wcsicmp((LPCTSTR)csToken, _T("/P")) == 0)
		{
			sMaxPipeData.sScanOptions.PromptToUser  = 1;
		}
        else if(_wcsicmp((LPCTSTR)csToken, _T("/T")) == 0)
		{
			sMaxPipeData.sScanOptions.CleanTempIE  = 1;
		}
		else if (_wcsicmp ((LPCTSTR )csToken,_T("/E"))== 0)
		{
			sMaxPipeData.sScanOptions.DeepScan   = 1;
		}
		else if (_wcsicmp ((LPCTSTR )csToken,_T("/L"))== 0)
		{
			sMaxPipeData.sScanOptions.LogOnly   = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/N"))== 0)
		{
			sMaxPipeData.sScanOptions.NoOutputInCMD = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/A"))== 0)
		{
			sMaxPipeData.sScanOptions.AutoQuarantine = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/PL"))== 0)
		{
			sMaxPipeData.sScanOptions.PluginScan = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/ML"))== 0)
		{
			sMaxPipeData.sScanOptions.MachineLearning = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/EX"))== 0)
		{
			sMaxPipeDataCmd.sScanOptionsCmd.ArchiveScan = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/CM"))== 0)
		{
			sMaxPipeDataCmd.sScanOptionsCmd.LogType = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/FL"))== 0)
		{
			sMaxPipeDataCmd.sScanOptionsCmd.LogLevel = 1;
		}
		else if ( _wcsicmp ((LPCTSTR )csToken,_T("/BG"))== 0)
		{
			sMaxPipeDataCmd.sScanOptionsCmd.BackGScanner = 1;
		}
		else if (_wcsicmp((LPCTSTR)csToken, _T("/AD")) == 0)	//ScanAlternateDataStream
		{
			sMaxPipeDataCmd.sScanOptionsCmd.ScanADStream = 1;
		}
		else if(wmemcmp((LPCTSTR)csToken, _T("/LOG:"), 5) == 0)
		{
	
			csToken = csCmdLineArg.Mid(iPos - (csToken.GetLength() + 1));
		
			int iPosLog = csToken.Find(L"/DRIVES:");
			if(iPosLog != -1)
			{
				csToken = csToken.Left(iPosLog);
				csToken.Replace(_T("/LOG:"), _T(""));
				csToken.Remove('"');
				wcscpy_s(sMaxPipeDataCmd.strPath, (LPCTSTR)csToken);
				_wcslwr_s(sMaxPipeDataCmd.strPath);	
				sMaxPipeDataCmd.sScanOptionsCmd.LogType = 1;
				
			}
		}
		else if(wmemcmp((LPCTSTR)csToken, _T("/DRIVES:"), 8) == 0)
		{
			csToken = csCmdLineArg.Mid(iPos - (csToken.GetLength() + 1));
			csToken.Replace(_T("/DRIVES:"), _T(""));
			csToken.Remove('"');
			wcscpy_s(sMaxPipeData.strValue, (LPCTSTR)csToken);
			_wcslwr_s(sMaxPipeData.strValue);
		}
		
		
#ifndef _STANDALONE_
		else if(wmemcmp((LPCTSTR)csToken, _T("/STANDALONE"), 11) == 0)
		{
			theApp.m_bStandAlone = true;
		}
#endif
		else if (wmemcmp((LPCTSTR)csToken, _T("/B:"), 3)== 0)
		{
			csToken.Replace(_T("/B:"), _T(""));
			wcscpy_s(sMaxPipeData.szGUID, csToken);
#ifndef _STANDALONE_
			theApp.m_csGUID = csToken;
#endif
		}
#ifdef _STANDALONE_
		else
		{
			if(sMaxPipeData.strValue == _T(""))
			{
				printf("Please Insert Proper arguments\r\nCheck Whether You have entered invalid argumrent\r\nCheck Whether You have entered arguments without space");
				return FALSE;
			}
		}
		if(sMaxPipeData.sScanOptions.RecoverSpyware == 1)
		{
			if(sMaxPipeData.sScanOptions.SignatureScan == 1 || sMaxPipeData.sScanOptions.VirusScan == 1 ||
				 sMaxPipeData.sScanOptions.RootkitScan == 1   || sMaxPipeData.sScanOptions.KeyLoggerScan == 1 ||
				 sMaxPipeData.sScanOptions.DBScan == 1        || sMaxPipeData.sScanOptions.CustomScan == 1)
			{
				printf("Please Insert Proper arguments\r\nCheck Whether You have entered invalid argumrent\r\nCheck Whether You have entered arguments without space");
				return FALSE;
			}
		}
//		if(sMaxPipeData.sScanOptions.CustomScan == 1)
//		{
//#ifdef WIN64
//			sMaxPipeData.sScanOptions.VirusScan = 0;
//#endif
//		}
#endif
		csToken = csCmdLineArg.Tokenize(L" ", iPos);
	}

	CMaxProtectionMgr oMaxProtectionMgr;
	if(sMaxPipeData.sScanOptions.HeuristicScan)
	{
		SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
		oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXSCANNER_HE);
	}
	else if(sMaxPipeData.sScanOptions.RegFixOptionScan)
	{
		oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXSCANNER_OPTION);
	}
	else if(sMaxPipeData.sScanOptions.IsUSBScanner)
	{
		oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXSCANNER_USB);
	}
	else
	{
		oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXSCANNER_MAIN);
	}

#ifndef _STANDALONE_
	theApp.m_pScannerThread  = AfxBeginThread(ScanInThread, this);
	if(sMaxPipeDataCmd.sScanOptionsCmd.BackGScanner == 1)
	{
		SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
	}
	
	//Pavan : Added Mutex to check scanner existence in memory before Merging
	CString csMutexName = _T("Global\\AU_SCANNER_ON");
	if (sMaxPipeData.sScanOptions.PluginScan != 1)
	{

		m_hGlobalMutex	= ::OpenMutex(SYNCHRONIZE, FALSE, csMutexName);
		if(m_hGlobalMutex == NULL)
		{
			m_hGlobalMutex = ::CreateMutex(NULL, TRUE, csMutexName);
		}
	}

	CString csMutexNameML = _T("Global\\AU_MLSCANNER_ON");
	if (sMaxPipeData.sScanOptions.MachineLearning == 1)
	{

		m_hGlobalMutexML	= ::OpenMutex(SYNCHRONIZE, FALSE, csMutexNameML);
		if(m_hGlobalMutexML == NULL)
		{
			m_hGlobalMutexML = ::CreateMutex(NULL, TRUE, csMutexNameML);
		}
	}

	CString csMutexNameBKG = _T("Global\\AU_BKGSCANNER_ON");
	if (sMaxPipeDataCmd.sScanOptionsCmd.BackGScanner == 1)
	{

		m_hGlobalMutexBKG	= ::OpenMutex(SYNCHRONIZE, FALSE, csMutexNameBKG);
		if(m_hGlobalMutexBKG == NULL)
		{
			m_hGlobalMutexBKG = ::CreateMutex(NULL, TRUE, csMutexNameBKG);
		}
	}

	
	WaitForSingleObject(theApp.m_pScannerThread->m_hThread, INFINITE);
	

	if(m_hGlobalMutex != NULL)
	{
		::ReleaseMutex(m_hGlobalMutex);
		m_hGlobalMutex = NULL;
	}

	if(m_hGlobalMutexML != NULL)
	{
		::ReleaseMutex(m_hGlobalMutexML);
		m_hGlobalMutexML = NULL;
	}
	if(m_hGlobalMutexBKG != NULL)
	{
		::ReleaseMutex(m_hGlobalMutexBKG);
		m_hGlobalMutexBKG = NULL;
	}
	

#else
	CWinThread *pThread  = AfxBeginThread(ScanInThread, this);
	WaitForSingleObject(pThread->m_hThread, INFINITE);
#endif

	return FALSE;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxInitScanner::StartScanner
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Siddharam Pujari.
--------------------------------------------------------------------------------------*/
void CMaxInitScanner::StartScanner()
{	
	if(sMaxPipeData.sScanOptions.Quarantine == 1)
	{
		CMaxDBScanner objMaxDBScanner;
		objMaxDBScanner.RestartQuarantine(&sMaxPipeData);
	}
#ifndef _STANDALONE_
	else if(sMaxPipeData.sScanOptions.QuarentineEntries == 1)
	{
		CQuarentineHandler objQuarentineHandler;
		objQuarentineHandler.StartQuarentineWithParams(&sMaxPipeData);		
	}
	else if(sMaxPipeData.sScanOptions.HeuristicScan == 1)
	{
		theApp.WDRegisterScanner(WD_StartingApp, Exit_Scanner, NOTIFY_PIPE, eHeuristic, 
								_NAMED_PIPE_HEURISTICSCAN_TO_SCANNER );

		CThreatCommunityHandler objThreatCommunity;
		objThreatCommunity.StartThreatCommunityScanning(&sMaxPipeData);

		theApp.WDRegisterScanner(WD_StoppingApp, Exit_Scanner, NOTIFY_PIPE, eHeuristic, 
								_NAMED_PIPE_HEURISTICSCAN_TO_SCANNER );
	}
#endif
	else if(sMaxPipeData.sScanOptions.RecoverSpyware == 1)
	{
		CRecoverHandler objRecoverHandler;
#ifndef _STANDALONE_
		theApp.WDRegisterScanner(WD_StartingApp, Finished_Recovery, RESTART_PROCESS, eScanner3, 
								_NAMED_PIPE_UI_TO_RECOVER_SCANNER);

		objRecoverHandler.StartRecoverHandler(&sMaxPipeData);
		theApp.WDRegisterScanner(WD_StoppingApp, Finished_Recovery, RESTART_PROCESS, eScanner3, 
								_NAMED_PIPE_UI_TO_RECOVER_SCANNER);
#else
		objRecoverHandler.StartCMDRecoverHandler(&sMaxPipeData);
#endif
	}
#ifndef _STANDALONE_
	else if(sMaxPipeData.sScanOptions.PluginScan == 1)
	{
		CPluginHandler objPluginHandler;
		if(objPluginHandler.IsThisFirstInstance())
		{
			theApp.WDRegisterScanner(WD_StartingApp, -1, RESTART_PROCESS, eOutlookPlugin, _NAMED_PIPE_PLUGIN_TO_SCANNER);
			objPluginHandler.StartPluginHandler(&sMaxPipeData);
			theApp.WDRegisterScanner(WD_StoppingApp, -1, RESTART_PROCESS, eOutlookPlugin, _NAMED_PIPE_PLUGIN_TO_SCANNER);
		}
	}
	else if(sMaxPipeData.sScanOptions.RegFixOptionScan == 1)
	{
		theApp.WDRegisterScanner(WD_StartingApp, Exit_Scanner, RESTART_PROCESS, eScanner2, 
								_NAMED_PIPE_OPTIONTTAB_TO_SCANNER );
		COptionHandler objOptionHandler;
		objOptionHandler.StartRegFixScanner(&sMaxPipeData);
		theApp.WDRegisterScanner(WD_StoppingApp, Exit_Scanner, RESTART_PROCESS, eScanner2, 
								_NAMED_PIPE_OPTIONTTAB_TO_SCANNER);
	}	
#endif
	else // default we run a db scan
	{
		E_TRUSTPID eTypeOfScanner = (sMaxPipeData.sScanOptions.IsUSBScanner == 1 ? eUSBScanner : eScanner1);
#ifndef _STANDALONE_
		theApp.WDRegisterScanner(WD_StartingApp, Report_Scanner_Failure, NOTIFY_PIPE, eTypeOfScanner,
							theApp.m_csGUID);
#endif
		CMaxDBScanner objMaxDBScanner;
		objMaxDBScanner.StartScanningWithParams(&sMaxPipeData, &sMaxPipeDataCmd);

#ifndef _STANDALONE_
		theApp.WDRegisterScanner(WD_StoppingApp, Report_Scanner_Failure, NOTIFY_PIPE, eTypeOfScanner,
								theApp.m_csGUID);
#endif
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxInitScanner::AppCrashHandler
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Siddharam Pujari
--------------------------------------------------------------------------------------*/
void CMaxInitScanner::AppCrashHandler()
{
	OutputDebugString(_T("SCANNER CRASHED!!!"));
}
