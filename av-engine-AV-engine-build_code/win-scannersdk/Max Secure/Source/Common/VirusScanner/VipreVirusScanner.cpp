/*======================================================================================
   FILE				: VipreVirusScanner.h
   ABSTRACT			: This class supports for scanning for Virus using Vipre Virus Scanner
						SDK 3.0
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created in 2008 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 20-Apr-2010
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#include "stdafx.h"
#include "BalBst.h"
#include "VipreVirusScanner.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: Constructor
In Parameters	: SENDMESSAGETOUI lpSndMessage
Out Parameters	: None
Purpose			: Init the base and this class object
Author			: Darshan Singh Virdi
Description		: init class variables
--------------------------------------------------------------------------------------*/
CVipreVirusScanner::CVipreVirusScanner(): m_hVipreDLL(NULL), m_VipreDispatcher(NULL)
{
}

/*-------------------------------------------------------------------------------------
Function		: Destructor
In Parameters	: None
Out Parameters	: None
Purpose			: If not already unloaded, it will unload the database, Deinitialize the dll
Author			: Darshan Singh Virdi
Description		: Deinit dll and unload virus database
--------------------------------------------------------------------------------------*/
CVipreVirusScanner::~CVipreVirusScanner()
{
}

/*-------------------------------------------------------------------------------------
Function		: InitializeVirusScanner
In Parameters	: const CString &csDBPath
Out Parameters	: bool, true is successfull else false
Purpose			: Initialize the vipre virus scanner dll, and loads the database
Author			: Darshan Singh Virdi
Description		: This function is not called in the constructor as it take approx 15 secs
					for vipre to load the database, hence its called only when a vipre
					scan is needed.
--------------------------------------------------------------------------------------*/
bool CVipreVirusScanner::InitializeVirusScanner(const CString &csDBPath)
{
	if(m_hVipreDLL && m_VipreDispatcher)
	{
		return true;
	}
	TCHAR szVPath[MAX_PATH] = {0};
	::GetModuleFileName(NULL,szVPath,MAX_PATH);
	LPTSTR szSlash = _tcsrchr(szVPath,_T('\\'));
	if(szSlash == NULL)
	{
		return false;
	}
	szSlash++;
	*szSlash = 0;
	_tcscat_s(szVPath,SS_VIPRE_SHIM_DLL);
	if(_taccess_s(szVPath, 0))
	{
		return false;
	}

	m_hVipreDLL = LoadLibrary(szVPath);
	if(m_hVipreDLL == NULL)
	{
		AddLogEntry(_T("Unable to find dynamic library %s"), szVPath);
		return false;
	}

	m_VipreDispatcher = (VIPRE_DISPATCHER)GetProcAddress(m_hVipreDLL, "vipreEventDispatcher");
	if(!m_VipreDispatcher)
	{
		// handle the error
		FreeLibrary(m_hVipreDLL);
		m_hVipreDLL = NULL;
		AddLogEntry(_T("%s DLL does not expose the correct API"), szVPath);
		return false;
	}

	TCHAR szDefinationPath[MAX_PATH] = {0};
	if(csDBPath.GetLength() != 0)
	{	
		_tcscpy_s(szDefinationPath, _countof(szDefinationPath), (LPCTSTR)csDBPath);		
	}
	else
	{
		if(!GetDefinitionsPath(szDefinationPath, MAX_PATH))
		{
			m_VipreDispatcher = NULL;
			FreeLibrary(m_hVipreDLL);
			m_hVipreDLL = NULL;
			AddLogEntry(_T("%s: Could not retrieve definition path!"), _T(__FUNCTION__));
			return false;
		}
	}

	VipreInitModuleParams initParms = {0};
	initParms.size				= sizeof(VipreInitModuleParams);
	initParms.logLevel			= LEV_MUTE;
	initParms.traceLevel		= TEV_MUTE;
	initParms.traceFn			= NULL;
	initParms.enhancedLogging	= false;
	initParms.dataFileDirspec	= szDefinationPath;

	bool ok = (m_VipreDispatcher(VIPRE_EV_STARTUP, (void*)&initParms) ? true : false);
	ok = (ok && initParms.completionStatus == SBS_OK);
	if (!ok)
	{
		m_VipreDispatcher = NULL;
		FreeLibrary(m_hVipreDLL);
		m_hVipreDLL = NULL;
		AddLogEntry(_T("%s: initialization error"), _T(__FUNCTION__));
		return false;
	}
	return true;
}

bool CVipreVirusScanner::GetDefinitionsPath(LPTSTR pwcsDefPath, DWORD dwBufLen)
{
	TCHAR szPath[MAX_PATH] = {0};
	if(!GetModuleFileName(NULL, szPath, _countof(szPath)))
	{
		return false;
	}

	if(_tcsrchr(szPath, _T('\\')))
	{
		*_tcsrchr(szPath, _T('\\'))= 0;
	}

	_tcscpy_s(pwcsDefPath, dwBufLen, szPath);
	_tcscat_s(pwcsDefPath, dwBufLen, _T("\\Definitions"));

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: DeInitializeVirusScanner
In Parameters	:
Out Parameters	: bool always true
Purpose			: It will unload the database, Deinitialize the dll
Author			: Darshan Singh Virdi
Description		: Unload the virus scanner dll and unload database
--------------------------------------------------------------------------------------*/
bool CVipreVirusScanner::DeInitializeVirusScanner()
{
	if(m_VipreDispatcher)
	{
		AddLogEntry(_T("UnLoading Vipre DLL!"));
		m_VipreDispatcher(VIPRE_EV_SHUTDOWN, NULL);
		m_VipreDispatcher = NULL;
	}
	if(m_hVipreDLL)
	{
		FreeLibrary(m_hVipreDLL);
		m_hVipreDLL = NULL;
	}
	return true;
}

void MTVCallBack(SBS_DISPOSITION_OBJECT_CB_EV eventId, SBS_OBJECT_DESCRIPTOR* objDesc);
void MTVScannerStatus(SBS_OBJECT_DESCRIPTOR* objDesc);

bool CVipreVirusScanner::ScanFile(PMAX_SCANNER_INFO pScanInfo)
{
	if(!m_VipreDispatcher)
	{
		return false;
	}

	m_bStopScanning = false;
	pScanInfo->pThis = this;
	pScanInfo->dwStartTickCount	= GetTickCount();

	VipreDispositionObjectParams dispObjParms = {0};
    dispObjParms.size = sizeof(VipreDispositionObjectParams);
    dispObjParms.dispCallback = MTVCallBack;
    dispObjParms.tempdir = _T("");
	dispObjParms.clientContext = (SBS_PVOID)pScanInfo;
	dispObjParms.pipelineMode = MODE_PRODUCTION;

	// pass the filepath to Vipre for scanning
	dispObjParms.flags = SBS_DISPOBJ_FL_TRY_PASSWORDS | 0; //m_dispositionHintFlags;
	dispObjParms.srcMapping = SBS_FILE_MAPPED;
	dispObjParms.buffer     = NULL;
	dispObjParms.buflen     = 0;
	dispObjParms.filepath   = (SBS_CHAR*)pScanInfo->szFileToScan;
	try
	{
		m_VipreDispatcher(VIPRE_EV_DISPOSITION_OBJECT, (void*)&dispObjParms);
	}
	catch(...)
	{
		OutputDebugString(_T("catch Exception in vipre Scaning"));
	}
	return ((dispObjParms.completionStatus == SBS_OK) ? true : false);
}

bool CVipreVirusScanner::RepairFile(PMAX_SCANNER_INFO pScanInfo)
{
	if(!m_VipreDispatcher)
	{
		return false;
	}

	m_bStopScanning = false;
	pScanInfo->pThis = this;
	pScanInfo->AutoQuarantine = 1;
	pScanInfo->dwStartTickCount	= GetTickCount();

	VipreDispositionObjectParams dispObjParms = {0};
    dispObjParms.size = sizeof(VipreDispositionObjectParams);
    dispObjParms.dispCallback = MTVCallBack;
    dispObjParms.tempdir = _T("");
	dispObjParms.clientContext = (SBS_PVOID)pScanInfo;
	dispObjParms.pipelineMode = MODE_PRODUCTION;

	// pass the filepath to Vipre for scanning
	dispObjParms.flags = SBS_DISPOBJ_FL_TRY_PASSWORDS | 0; //m_dispositionHintFlags;
	dispObjParms.srcMapping = SBS_FILE_MAPPED;
	dispObjParms.buffer     = NULL;
	dispObjParms.buflen     = 0;
	dispObjParms.filepath   = (SBS_CHAR*)pScanInfo->szFileToScan;

	try
	{
		m_VipreDispatcher(VIPRE_EV_DISPOSITION_OBJECT, (void*)&dispObjParms);
	}
	catch(...)
	{
	}
	return ((dispObjParms.completionStatus == SBS_OK) ? true : false);
}

void MTVCallBack(SBS_DISPOSITION_OBJECT_CB_EV eventId, SBS_OBJECT_DESCRIPTOR* objDesc)
{
	PMAX_SCANNER_INFO pScanInfo = (PMAX_SCANNER_INFO)objDesc->clientContext;
	if(!pScanInfo)
	{
		objDesc->prevClientAction = CLNT_ACT_ABORT_PROCESSING;
		objDesc->clientAction = CLNT_ACT_ABORT_PROCESSING;
		return;
	}

	if((GetTickCount() - pScanInfo->dwStartTickCount) >= MAX_SCAN_TIME)
	{
		pScanInfo->ThreatNonCurable = true;
		objDesc->prevClientAction = CLNT_ACT_ABORT_PROCESSING;
		objDesc->clientAction = CLNT_ACT_ABORT_PROCESSING;
		return;
	}

	if(((CVipreVirusScanner*)(pScanInfo->pThis))->m_bStopScanning)
	{
		objDesc->prevClientAction = CLNT_ACT_ABORT_PROCESSING;
		objDesc->clientAction = CLNT_ACT_ABORT_PROCESSING;
		return;
	}

	if(objDesc->isArchive)	// can be a setup or zip
	{
		pScanInfo->IsArchiveFile = true;
	}
	if(objDesc->packerId)	// can be a setup or zip
	{
		pScanInfo->IsPackedFile = true;
	}
    switch(eventId) 
    {
	case DOE_OBJECT_REMEDIATE_COMPLETE:
	case DOE_ARCHIVE_REMEDIATE_COMPLETE:
		{
			MTVScannerStatus(objDesc);
			if(pScanInfo->AutoQuarantine)
			{
				if(objDesc->remedActionTaken == SBS_REM_REPAIR)
				{
					AddLogEntry(L"##### VVS-R-S    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					pScanInfo->ThreatRepaired = true;
				}
				else if(objDesc->remedActionTaken == SBS_REM_DELETE)
				{
					AddLogEntry(L"##### VVS-Q-S    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					pScanInfo->ThreatQuarantined = true;
				}
				else if(objDesc->remedActionTaken == SBS_REM_IGNORE)
				{
					AddLogEntry(L"----- VVS-R-F    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					pScanInfo->ThreatNonCurable = true;
				}
			}
		}
		break;
	case DOE_ARCHIVE_DISPOSITION_BEGUN:
		{
		}
		break;
	case DOE_ARCHIVE_ENCRYPTED:
		{
			pScanInfo->IsPasswordProtected = true;
			objDesc->clientAction = CLNT_ACT_ABORT_PROCESSING;	// no password available!
		}
		break;
	case DOE_ARCHIVE_DISPOSITION_COMPLETE:
		{
		}
		break;
	case DOE_OBJECT_DISPOSITION_COMPLETE:
		{
			if(pScanInfo)
			{
				MTVScannerStatus(objDesc);
				if((pScanInfo->AutoQuarantine) && (objDesc->threatId != 0))
				{
					if(objDesc->vipreFlags & SBS_DISPOBJ_DF_FILE_INFECTOR)
					{
						// file is infected, clean it regardless of whether it's in archive.
						objDesc->clientAction = CLNT_ACT_CLEAN_FILE;
					}
					else if(objDesc->archivePath != NULL)
					{
						// it's an archive member
						// rename foo.bar -> foo.bar.cleaned and overwrite its contents with this
						objDesc->replaceContent = SS_DEFAULT_CONTENT_REPLACE_STRING;
						objDesc->clientAction = CLNT_ACT_REPLACE_FILE;
					}
					else
					{
						// just delete the file
						objDesc->clientAction = CLNT_ACT_DELETE_FILE;
					}
				}
				else
				{
					objDesc->clientAction = CLNT_ACT_CONTINUE_PROCESSING;
				}
			}
			else
			{
				objDesc->clientAction = CLNT_ACT_CONTINUE_PROCESSING;
			}
		}
        break;
	case DOE_DISPOSITION_STATUS:
		{
			objDesc->clientAction = CLNT_ACT_CONTINUE_PROCESSING;
		}
		break;
    }
}

void MTVScannerStatus(SBS_OBJECT_DESCRIPTOR* objDesc)
{
	PMAX_SCANNER_INFO pScanInfo = (PMAX_SCANNER_INFO)objDesc->clientContext;
	if(!pScanInfo)
	{
		return;
	}
	SBS_CHAR *file_path = objDesc->filePath;
	if(objDesc->archivePath != NULL)
	{
		if(objDesc->parent)
		{
			file_path = objDesc->parent->filePath;
		}
	}
	switch(objDesc->opStatus)
	{
	case SBS_OK:
		break;
	case SBS_KNOWN_BAD:          // blacklisted or threat detected
		{
			if(pScanInfo->ThreatDetected)
			{
				pScanInfo->MultipleInfection = true;
			}
			pScanInfo->eDetectedBY = Detected_BY_Vipre;
			pScanInfo->ThreatDetected = true;
			if((objDesc->vipreFlags & SBS_DISPOBJ_DF_FILE_INFECTOR) || (objDesc->archivePath != NULL))
			{
				pScanInfo->eMessageInfo = Virus_File_Repair;
				_tcscpy_s(pScanInfo->szThreatName, MAX_PATH, objDesc->threatName);
				AddLogEntry(L"##### VVS-R      : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
			}
			else
			{
				pScanInfo->eMessageInfo = Virus_File;
				_tcscpy_s(pScanInfo->szThreatName, MAX_PATH, objDesc->threatName);
				AddLogEntry(L"##### VVS-Q      : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
			}
		}
		break;
	case SBS_KNOWN_GOOD:         // whitelisted
		break;
	case SBS_NO_THREAT:          // no threat detected
		break;
	case SBS_UNKNOWN_OBJECT_TYPE: // cant classify object
		break;
	case SBS_CONTAINER_RECURSION_LIMIT:
		break;
	case SBS_CORRUPTED_OBJECT:
		break;
	case SBS_ENCRYPTED_OBJECT:
		break;
	case SBS_SUSPICIOUS_OBJECT:
		{
			if(pScanInfo->ThreatSuspicious)
			{
				pScanInfo->MultipleInfection = true;
			}
			pScanInfo->eDetectedBY = Detected_BY_Vipre;
			pScanInfo->ThreatSuspicious = true;
			if((objDesc->vipreFlags & SBS_DISPOBJ_DF_FILE_INFECTOR) || (objDesc->archivePath != NULL))
			{
				pScanInfo->eMessageInfo = Virus_File_Repair;
				_tcscpy_s(pScanInfo->szThreatName, MAX_PATH, objDesc->threatName);
				AddLogEntry(L"##### VVS-R      : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
			}
			else
			{
				pScanInfo->eMessageInfo = Virus_File;
				_tcscpy_s(pScanInfo->szThreatName, MAX_PATH, objDesc->threatName);
				AddLogEntry(L"##### VVS-Q      : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
			}
		}
		break;
	case SBS_REQUIRE_PARENT:
		if((pScanInfo->ThreatDetected) || (pScanInfo->ThreatSuspicious))
		{
			pScanInfo->ThreatNonCurable = true;
		}
		break;
	case SBS_ZERO_SIZE:
		if((pScanInfo->ThreatDetected) || (pScanInfo->ThreatSuspicious))
		{
			pScanInfo->ThreatNonCurable = true;
		}
		break;
	default:
		break;
	}
}