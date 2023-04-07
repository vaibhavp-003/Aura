/*=============================================================================
   FILE		           : UpdateManager.cpp
   ABSTRACT		       : 
   DOCUMENTS	       : Refer The Live Update Design.doc, Live Update Requirement Document.doc
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 2/3/2005
   NOTES		      : implementation file
   VERSION HISTORY    : 
						Date: 17 March 2008
						Resource: Avinash Bhardwaj
						Description : porting to 2005.
						Date: 27 Feb 2010
						Resource: Tejas
						Description: Restart active protection after network db update
						
=============================================================================*/
#include <pch.h>
#include "UpdateManager.h"
#include "BackupOperations.h"
#include "SDSystemInfo.h"
#include "Registry.h"

/*--------------------------------------------------------------------------------------
Function       : CUpdateManager
In Parameters  : void
Out Parameters :
Description    : constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CUpdateManager::CUpdateManager(void):
				m_objCookieDB(false), m_objFileDB(false), m_objFolderDB(false),
				m_objRegKeyDB(false), m_objRegValDB(false),
				m_objNameDBMap(true), m_objVirusR(false),
				m_objVirusSPE(false), m_objVirusSDos(false),
				m_objVirusSCom(false), m_objVirusSWMA(false),
				m_objVirusSSCRIPT(false), m_objVirusSOLE(false),
				m_objVirusSINF(false), m_objVirusSPDF(false), m_objVirusSSIS(false),
				m_objVirusSDEX(false), m_objVirusSRTF(false), m_objVirusSCURSOR(false),
				m_objAntiBanner(false, sizeof(DWORD), sizeof(URLDATA), sizeof(DWORD)), 
				m_objAntiPhishing(false, sizeof(DWORD), sizeof(URLDATA), sizeof(DWORD))

{
	m_csDeltaFileName = _T("");
	m_bVirusDBUpdated = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CUpdateManager
In Parameters  : void, 
Out Parameters :
Description    : Destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CUpdateManager::~CUpdateManager(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : MergeThreatNameDB
In Parameters  : 
Out Parameters : bool
Description    : Read and update Spyware Name DB
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::MergeThreatNameDB()
{
	AddLogEntry(_T("Start Merging for: %s"), SD_DB_SPYNAME, 0, true, LOG_WARNING);

	if(m_objNameDBMap.AddDBFile(m_csDeltaFileName + _T("\\a") + CString(SD_DB_SPYNAME)))
	{
		AddLogEntry(_T("Error merging: a%s"), SD_DB_SPYNAME);
		return false;
	}

	AddLogEntry(_T("End Merging for: %s"), SD_DB_SPYNAME, 0, true, LOG_WARNING);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : MergeRegFixDB
In Parameters  :
Out Parameters : bool
Description    : Read and Update RegFix DB
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::MergeRegFixDB()
{
	CRegFix objDeltaRegFix;
	bool bMergeSuccess = true;

	AddLogEntry(_T("Start Merging for : %s"), SD_DB_REGFIX, 0, true, LOG_WARNING);
	if(!_taccess_s(m_csDeltaFileName + _T("\\a") + SD_DB_REGFIX, 0))
	{
		if(objDeltaRegFix.Load(m_csDeltaFileName + _T("\\a") + SD_DB_REGFIX))
		{
			bMergeSuccess = m_objRegFix.AppendObject(objDeltaRegFix) ? bMergeSuccess : false;
			objDeltaRegFix.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: a%s"), SD_DB_REGFIX);
			return bMergeSuccess;
		}
	}

	if(!_taccess_s(m_csDeltaFileName + _T("\\d") + SD_DB_REGFIX, 0))
	{
		if(objDeltaRegFix.Load(m_csDeltaFileName + _T("\\d") + SD_DB_REGFIX))
		{
			bMergeSuccess = m_objRegFix.DeleteObject(objDeltaRegFix) ? bMergeSuccess : false;
			objDeltaRegFix.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: d%s"), SD_DB_REGFIX);
			return bMergeSuccess;
		}
	}

	AddLogEntry(_T("End Merging for : %s"), SD_DB_REGFIX, 0, true, LOG_WARNING);
	return bMergeSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : MergeBalBSTDB
In Parameters  : CString csDBName, CBalBST& objMainDB, CBalBST& objDeltaDB
Out Parameters : bool
Description    : merge delta db
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUpdateManager::MergeBalBSTDB(const CString &csDBName, CBalBST& objMainDB, CBalBST& objDeltaDB)
{
	bool bMergeSuccess = true;
	CString csFullFilePath;

	AddLogEntry(_T("Start Merging for: %s"), csDBName, 0, true, LOG_WARNING);
	csFullFilePath = m_csDeltaFileName + _T("\\a") + csDBName;

	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.AppendObject(objDeltaDB) ? bMergeSuccess : false;
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: a%s"), csDBName);
			return bMergeSuccess;
		}
	}
	
	csFullFilePath = m_csDeltaFileName + _T("\\d") + csDBName;
	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.DeleteObject(objDeltaDB) ? bMergeSuccess : false;
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: d%s"), csDBName);
			return bMergeSuccess;
		}
	}

	AddLogEntry(_T("End Merging for: %s"), csDBName, 0, true, LOG_WARNING);
	return bMergeSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : MergeBalBSTOptDB
In Parameters  : CString csDBName, CFSDB& objMainDB, CFSDB& objDeltaDB
Out Parameters : bool
Description    : merge delta db
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CUpdateManager::MergeBalBSTOptDB(const CString &csDBName, CFSDB& objMainDB, CFSDB& objDeltaDB)
{
	CString csFullFilePath;
	bool bMergeSuccess = true;
	//int	iError = 0x00;

	AddLogEntry(_T("Start Merging for: %s"), csDBName, 0, true, LOG_WARNING);
	csFullFilePath = m_csDeltaFileName + _T("\\a") + csDBName;

	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.AppendObject(objDeltaDB) ? bMergeSuccess : false;
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: a%s"), csDBName);
			return bMergeSuccess;
		}
	}
	
	csFullFilePath = m_csDeltaFileName + _T("\\d") + csDBName;
	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.DeleteObject(objDeltaDB) ? bMergeSuccess : false;
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: d%s"), csDBName);
			return bMergeSuccess;
		}
	}
	

	/*
	if(SD_DB_FS_WHT == csDBName)
	{
		csFullFilePath = m_csDeltaFileName + _T("\\a") + SD_DB_FS_BLK;
		if(!_taccess_s(csFullFilePath, 0))
		{
			if(objDeltaDB.Load(csFullFilePath))
			{
				bMergeSuccess = objMainDB.DeleteObject(objDeltaDB) ? bMergeSuccess : false;
				objDeltaDB.RemoveAll();
			}

			if(!bMergeSuccess)
			{
				AddLogEntry(_T("Error merging: a%s"), SD_DB_FS_BLK);
				return bMergeSuccess;
			}
		}
	}
	*/
	AddLogEntry(_T("End merging for: %s"), csDBName, 0, true, LOG_WARNING);
	return bMergeSuccess;
}


/*--------------------------------------------------------------------------------------
Function       : MergeBalBSTOptDB
In Parameters  : CString csDBName, CFSDB& objMainDB, CFSDB& objDeltaDB
Out Parameters : bool
Description    : merge delta db
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
//bool CUpdateManager::MergeBalBSTOptDB(const CString &csDBName, CBlackDBManager& objMainDB, CFSDB& objDeltaDB)
bool CUpdateManager::MergeBalBSTOptDB(const CString &csDBName, CBlackDBManager& objMainDB, CMaxNewPESig& objDeltaDB)
{
	CString csFullFilePath;
	bool bMergeSuccess = true;

	AddLogEntry(_T("Start Merging for: %s"), csDBName, 0, true, LOG_WARNING);
	csFullFilePath = m_csDeltaFileName + _T("\\a") + csDBName;

	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.AppendObject(objDeltaDB) ? bMergeSuccess : false;
			
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: a%s"), csDBName);
			return bMergeSuccess;
		}
	}

	csFullFilePath = m_csDeltaFileName + _T("\\d") + csDBName;
	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.DeleteObject(objDeltaDB) ? bMergeSuccess : false;
			
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: d%s"), csDBName);
			return bMergeSuccess;
		}
	}

	if(SD_DB_FS_WHT == csDBName)
	{
		csFullFilePath = m_csDeltaFileName + _T("\\a") + SD_DB_FS_BLK;
		if(!_taccess_s(csFullFilePath, 0))
		{
			if(objDeltaDB.Load(csFullFilePath))
			{
				bMergeSuccess = objMainDB.DeleteObject(objDeltaDB) ? bMergeSuccess : false;
				objDeltaDB.RemoveAll();
			}

			if(!bMergeSuccess)
			{
				AddLogEntry(_T("Error merging: a%s"), SD_DB_FS_BLK);
				return bMergeSuccess;
			}
		}
	}

	AddLogEntry(_T("End merging for: %s"), csDBName, 0, true, LOG_WARNING);
	return bMergeSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : MergeBalBSTFWDB
In Parameters  : CString csDBName, CBalBSTOpt& objMainDB, CBalBSTOpt& objDeltaDB
Out Parameters : bool
Description    : merge delta db
Author         : Sid
--------------------------------------------------------------------------------------*/
bool CUpdateManager::MergeBalBSTOptFWDB(const CString &csDBName, CBalBSTOpt& objMainDB, CBalBSTOpt& objDeltaDB)
{
	bool bMergeSuccess = true;
	CString csFullFilePath;

	AddLogEntry(_T("Start Merging for: %s"), csDBName, 0, true, LOG_WARNING);
	csFullFilePath = m_csDeltaFileName + _T("\\a") + csDBName;

	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.AppendObject(objDeltaDB) ? bMergeSuccess : false;
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: a%s"), csDBName);
			return bMergeSuccess;
		}
	}

	csFullFilePath = m_csDeltaFileName + _T("\\d") + csDBName;
	if(!_taccess_s(csFullFilePath, 0))
	{
		if(objDeltaDB.Load(csFullFilePath))
		{
			bMergeSuccess = objMainDB.DeleteObject(objDeltaDB) ? bMergeSuccess : false;
			objDeltaDB.RemoveAll();
		}

		if(!bMergeSuccess)
		{
			AddLogEntry(_T("Error merging: d%s"), csDBName);
			return bMergeSuccess;
		}
	}

	AddLogEntry(_T("End Merging for: %s"), csDBName, 0, true, LOG_WARNING);
	return bMergeSuccess;
}
/*--------------------------------------------------------------------------------------
Function       : LoadDBType
In Parameters  : long lType, 
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::LoadDBType(const CString &csDataFolder, long lType, CString * pcsFileName, bool bLoadFirewallDB)
{
	bool bLoadSuccess = true;

	if(lType == 0)
	{
		if(m_objNameDBMap.Load(csDataFolder + SD_DB_SPYNAME))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_SPYNAME, 0, true, LOG_WARNING);
		}
		else
		{
			if(pcsFileName)
			{
				TCHAR szCateFileName[MAX_PATH] = {0}, szNameFileName[MAX_PATH] = {0}, szIDFileName[MAX_PATH] = {0};
				m_objNameDBMap.PrepareFileNames(SD_DB_SPYNAME, szCateFileName, _countof(szCateFileName), szNameFileName,
												_countof(szNameFileName), szIDFileName, _countof(szIDFileName));

				AddFileNameToFailedList(pcsFileName, SD_DB_SPYNAME);
				AddFileNameToFailedList(pcsFileName, szCateFileName);
				AddFileNameToFailedList(pcsFileName, szNameFileName);
				AddFileNameToFailedList(pcsFileName, szIDFileName);
			}

			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_SPYNAME, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 1)
	{
		if(m_objFileDB.Load(csDataFolder + SD_DB_FILE))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_FILE, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_FILE);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_FILE, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 2)
	{
		if(m_objFolderDB.Load(csDataFolder + SD_DB_FOLDER))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_FOLDER, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_FOLDER);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_FOLDER, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 3)
	{
		if(m_objCookieDB.Load(csDataFolder + SD_DB_COOKIES))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_COOKIES, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_COOKIES);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_COOKIES, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 4)
	{
		if(m_objRegKeyDB.Load(csDataFolder + SD_DB_REGKEY))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_REGKEY, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_REGKEY);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_REGKEY, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 5)
	{
		/*if(m_objPESigB.Load(csDataFolder + SD_DB_FS_BLK))*/
		AddLogEntry(_T("Going for loading all DB: %s"), csDataFolder, 0, true, LOG_WARNING);
		if(m_objBlackDBManager.Load(csDataFolder))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_FS_BLK);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 6)
	{
		CString csFailedFileNames;

		if(m_objPESigW.Load(csDataFolder + SD_DB_FS_WHT))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_FS_WHT, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_FS_WHT);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_FS_WHT, 0, true, LOG_WARNING);
		}

		if(m_objPESigQ.Load(csDataFolder + SD_DB_FS_QIK))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_FS_QIK, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_FS_QIK);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_FS_QIK, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 7)
	{
		if(m_objRegFix.Load(csDataFolder + SD_DB_REGFIX))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_REGFIX, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_REGFIX);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_REGFIX, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 8)
	{
		if(m_objRegValDB.Load(csDataFolder + SD_DB_REGVAL))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_REGVAL, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_REGVAL);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_REGVAL, 0, true, LOG_WARNING);
		}
	}
	else if(lType == 9)
	{
		if(m_objVirusR.Load(csDataFolder + VIRUS_DB_REPAIR))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_REPAIR, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_REPAIR);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_REPAIR, 0, true, LOG_WARNING);
		}

		if(m_objVirusSPE.Load(csDataFolder + VIRUS_DB_PE_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_PE_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_PE_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_PE_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSDos.Load(csDataFolder + VIRUS_DB_DOS_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_DOS_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_DOS_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_DOS_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSCom.Load(csDataFolder + VIRUS_DB_COM_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_COM_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_COM_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_COM_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSWMA.Load(csDataFolder + VIRUS_DB_WMA_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_WMA_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_WMA_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_WMA_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSSCRIPT.Load(csDataFolder + VIRUS_DB_SCRIPT_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_SCRIPT_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_SCRIPT_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_SCRIPT_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSOLE.Load(csDataFolder + VIRUS_DB_OLE_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_OLE_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_OLE_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_OLE_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSINF.Load(csDataFolder + VIRUS_DB_INF_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_INF_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_INF_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_INF_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSPDF.Load(csDataFolder + VIRUS_DB_PDF_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_PDF_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_PDF_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_PDF_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSSIS.Load(csDataFolder + VIRUS_DB_SIS_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_SIS_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_SIS_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_SIS_SIG, 0, true, LOG_WARNING);
		}

		if(m_objVirusSDEX.Load(csDataFolder + VIRUS_DB_DEX_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_DEX_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_DEX_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_DEX_SIG, 0, true, LOG_WARNING);
		}
		if(m_objVirusSRTF.Load(csDataFolder + VIRUS_DB_RTF_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_RTF_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_RTF_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_RTF_SIG, 0, true, LOG_WARNING);
		}
		if(m_objVirusSCURSOR.Load(csDataFolder + VIRUS_DB_CURSOR_SIG))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + VIRUS_DB_CURSOR_SIG, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, VIRUS_DB_CURSOR_SIG);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + VIRUS_DB_CURSOR_SIG, 0, true, LOG_WARNING);
		}
		m_csMergeTempDataFolder = csDataFolder;
	}
	else if(lType == 10)
	{
		if((CSystemInfo::m_csProductNumber == L"18") && (bLoadFirewallDB || CSystemInfo::m_bIsFirewallInstalled))
		{
			if(m_objAntiBanner.Load(csDataFolder + SD_DB_ANTI_BANNER))
			{
				AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_ANTI_BANNER, 0, true, LOG_WARNING);
			}
			else
			{
				AddFileNameToFailedList(pcsFileName, SD_DB_ANTI_BANNER);
				bLoadSuccess = false;
				AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_ANTI_BANNER, 0, true, LOG_WARNING);
			}
		}
		else
		{
			bLoadSuccess = true;
		}
	}
	else if(lType == 11)
	{
		if((CSystemInfo::m_csProductNumber == L"18") && (bLoadFirewallDB || CSystemInfo::m_bIsFirewallInstalled))
		{
			if(m_objAntiPhishing.Load(csDataFolder + SD_DB_ANTI_PHISHING))
			{
				AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_ANTI_PHISHING, 0, true, LOG_WARNING);
			}
			else
			{
				AddFileNameToFailedList(pcsFileName, SD_DB_ANTI_PHISHING);
				bLoadSuccess = false;
				AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_ANTI_PHISHING, 0, true, LOG_WARNING);
			}
		}
		else
		{
			bLoadSuccess = true;
		}
	}
	else if(lType == 12)
	{
		if(m_objPESigFFS.Load(csDataFolder + SD_DB_FS_FULLFILE_MD5))
		{
			AddLogEntry(_T("Success loading: %s"), csDataFolder + SD_DB_FS_FULLFILE_MD5, 0, true, LOG_WARNING);
		}
		else
		{
			AddFileNameToFailedList(pcsFileName, SD_DB_FS_FULLFILE_MD5);
			bLoadSuccess = false;
			AddLogEntry(_T("Failure loading: %s"), csDataFolder + SD_DB_FS_FULLFILE_MD5, 0, true, LOG_WARNING);
		}
	}

	return bLoadSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : SaveDBType
In Parameters  : long lType, 
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::SaveDBType(const CString &csDataFolder, long lType, bool bSaveFirewallDB)
{
	bool bSaveSuccess = true;
	if(lType == 0)
	{
		if(m_objNameDBMap.IsModified())
		{
			m_objNameDBMap.Balance();
			bSaveSuccess = m_objNameDBMap.Save(csDataFolder + SD_DB_SPYNAME)?bSaveSuccess:false;
		}
		m_objNameDBMap.RemoveAll();
	}
	else if(lType == 1)
	{
		if(m_objFileDB.IsModified())
		{
			m_objFileDB.Balance();
			bSaveSuccess = m_objFileDB.Save(csDataFolder + SD_DB_FILE)?bSaveSuccess:false;
		}
		m_objFileDB.RemoveAll();
	}
	else if(lType == 2)
	{
		if(m_objFolderDB.IsModified())
		{
			m_objFolderDB.Balance();
			bSaveSuccess = m_objFolderDB.Save(csDataFolder + SD_DB_FOLDER)?bSaveSuccess:false;
		}
		m_objFolderDB.RemoveAll();
	}
	else if(lType == 3)
	{
		if(m_objCookieDB.IsModified())
		{
			m_objCookieDB.Balance();
			bSaveSuccess = m_objCookieDB.Save(csDataFolder + SD_DB_COOKIES)?bSaveSuccess:false;
		}
		m_objCookieDB.RemoveAll();
	}
	else if(lType == 4)
	{
		if(m_objRegKeyDB.IsModified())
		{
			m_objRegKeyDB.Balance();
			bSaveSuccess = m_objRegKeyDB.Save(csDataFolder + SD_DB_REGKEY)?bSaveSuccess:false;
		}
		m_objRegKeyDB.RemoveAll();
	}
	else if(lType == 5)
	{
		if(m_objBlackDBManager.IsModified())
		{
			bool bRetValue = false;
			m_objBlackDBManager.Balance();
			bRetValue = m_objBlackDBManager.Save(csDataFolder);
			bSaveSuccess = bRetValue? bSaveSuccess:false;
			if(!bRetValue)
			{
				AddLogEntry(L"Failed to save SD_DB_FS_BLK(SD43.DB). EPMD5UPDATE=1.");
				CRegistry objReg;
				objReg.SetWow64Key((objReg.IsOS64Bit() ? true : false));
				objReg.Set(CSystemInfo::m_csProductRegKey, _T("FULLLIVEUPDATE"), 0, HKEY_LOCAL_MACHINE);
				objReg.Set(CSystemInfo::m_csProductRegKey, _T("EPMD5UPDATE"), 1, HKEY_LOCAL_MACHINE);
			}
		}
		m_objBlackDBManager.RemoveAll();
	}
	else if(lType == 6)
	{
		if(m_objPESigW.IsModified())
		{
			m_objPESigW.Balance();
			bSaveSuccess = m_objPESigW.Save(csDataFolder + SD_DB_FS_WHT)?bSaveSuccess:false;
		}
		m_objPESigW.RemoveAll();

		if(m_objPESigQ.IsModified())
		{
			m_objPESigQ.Balance();
			bSaveSuccess = m_objPESigQ.Save(csDataFolder + SD_DB_FS_QIK)?bSaveSuccess:false;
		}
		m_objPESigQ.RemoveAll();
	}
	else if(lType == 7)
	{
		bSaveSuccess = m_objRegFix.Save(csDataFolder + SD_DB_REGFIX)?bSaveSuccess:false;
		m_objRegFix.RemoveAll();
	}
	else if(lType == 8)
	{
		if(m_objRegValDB.IsModified())
		{
			m_objRegValDB.Balance();
			bSaveSuccess = m_objRegValDB.Save(csDataFolder + SD_DB_REGVAL)?bSaveSuccess:false;
		}
		m_objRegValDB.RemoveAll();		
	}
	else if(lType == 9)
	{
		if(m_objVirusR.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusR.Balance();
			bSaveSuccess = m_objVirusR.Save(csDataFolder + VIRUS_DB_REPAIR)?bSaveSuccess:false;
		}
		m_objVirusR.RemoveAll();	

		if(m_objVirusSPE.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSPE.Balance();
			bSaveSuccess = m_objVirusSPE.Save(csDataFolder + VIRUS_DB_PE_SIG)?bSaveSuccess:false;
		}
		m_objVirusSPE.RemoveAll();

		if(m_objVirusSDos.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSDos.Balance();
			bSaveSuccess = m_objVirusSDos.Save(csDataFolder + VIRUS_DB_DOS_SIG)?bSaveSuccess:false;
		}
		m_objVirusSDos.RemoveAll();

		if(m_objVirusSCom.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSCom.Balance();
			bSaveSuccess = m_objVirusSCom.Save(csDataFolder + VIRUS_DB_COM_SIG)?bSaveSuccess:false;
		}
		m_objVirusSCom.RemoveAll();

		if(m_objVirusSWMA.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSWMA.Balance();
			bSaveSuccess = m_objVirusSWMA.Save(csDataFolder + VIRUS_DB_WMA_SIG)?bSaveSuccess:false;
		}
		m_objVirusSWMA.RemoveAll();

		if(m_objVirusSSCRIPT.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSSCRIPT.Balance();
			bSaveSuccess = m_objVirusSSCRIPT.Save(csDataFolder + VIRUS_DB_SCRIPT_SIG)?bSaveSuccess:false;
		}
		m_objVirusSSCRIPT.RemoveAll();

		if(m_objVirusSOLE.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSOLE.Balance();
			bSaveSuccess = m_objVirusSOLE.Save(csDataFolder + VIRUS_DB_OLE_SIG)?bSaveSuccess:false;
		}
		m_objVirusSOLE.RemoveAll();

		if(m_objVirusSINF.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSINF.Balance();
			bSaveSuccess = m_objVirusSINF.Save(csDataFolder + VIRUS_DB_INF_SIG)? bSaveSuccess: false;
		}
		m_objVirusSINF.RemoveAll();

		if(m_objVirusSPDF.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSPDF.Balance();
			bSaveSuccess = m_objVirusSPDF.Save(csDataFolder + VIRUS_DB_PDF_SIG)? bSaveSuccess: false;
		}
		m_objVirusSPDF.RemoveAll();

		if(m_objVirusSSIS.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSSIS.Balance();
			bSaveSuccess = m_objVirusSSIS.Save(csDataFolder + VIRUS_DB_SIS_SIG)? bSaveSuccess: false;
		}
		m_objVirusSSIS.RemoveAll();

		if(m_objVirusSDEX.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSDEX.Balance();
			bSaveSuccess = m_objVirusSDEX.Save(csDataFolder + VIRUS_DB_DEX_SIG)? bSaveSuccess: false;
		}
		m_objVirusSDEX.RemoveAll();
		if(m_objVirusSRTF.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSRTF.Balance();
			bSaveSuccess = m_objVirusSRTF.Save(csDataFolder + VIRUS_DB_RTF_SIG)? bSaveSuccess: false;
		}
		m_objVirusSRTF.RemoveAll();
		if(m_objVirusSCURSOR.IsModified())
		{
			m_bVirusDBUpdated = true;
			m_objVirusSCURSOR.Balance();
			bSaveSuccess = m_objVirusSCURSOR.Save(csDataFolder + VIRUS_DB_CURSOR_SIG)? bSaveSuccess: false;
		}
		m_objVirusSCURSOR.RemoveAll();
	}
	else if(lType == 10)
	{
		if((CSystemInfo::m_csProductNumber == L"18") && (bSaveFirewallDB  || CSystemInfo::m_bIsFirewallInstalled))
		{
			if(m_objAntiBanner.IsModified())
			{
				m_objAntiBanner.Balance();
				bSaveSuccess = m_objAntiBanner.Save(csDataFolder + SD_DB_ANTI_BANNER)?bSaveSuccess:false;
			}
		}
		else
		{
			bSaveSuccess = true;
		}
		m_objAntiBanner.RemoveAll();		
	}
	else if(lType == 11)
	{
		if((CSystemInfo::m_csProductNumber == L"18") && (bSaveFirewallDB  || CSystemInfo::m_bIsFirewallInstalled))
		{
			if(m_objAntiPhishing.IsModified())
			{
				m_objAntiPhishing.Balance();
				bSaveSuccess = m_objAntiPhishing.Save(csDataFolder + SD_DB_ANTI_PHISHING)?bSaveSuccess:false;
			}
		}
		else
		{
			bSaveSuccess = true;
		}
		m_objAntiPhishing.RemoveAll();
	}
	else if(lType == 12)
	{
		if(m_objPESigFFS.IsModified())
		{
			m_objPESigFFS.Balance();
			bSaveSuccess = m_objPESigFFS.Save(csDataFolder + SD_DB_FS_FULLFILE_MD5)?bSaveSuccess:false;
		}
		m_objPESigFFS.RemoveAll();		
	}

	return bSaveSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : MergeDBType
In Parameters  : long lType
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::MergeDBType(long lType,  bool bMergeFirewallDB)
{
	bool bMergeSuccess = true;
	if(lType == 0)
	{
		bMergeSuccess = MergeThreatNameDB() ? bMergeSuccess : false;
	}
	else if(lType == 1)
	{
		CU2OU2O objDelta(false);
		bMergeSuccess = MergeBalBSTDB(SD_DB_FILE, m_objFileDB, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 2)
	{
		CU2OU2O objDelta(false);
		bMergeSuccess = MergeBalBSTDB(SD_DB_FOLDER, m_objFolderDB, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 3)
	{
		CS2U objDelta(false);
		bMergeSuccess = MergeBalBSTDB(SD_DB_COOKIES, m_objCookieDB, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 4)
	{
		CU2OU2O objDelta(false);
		bMergeSuccess = MergeBalBSTDB(SD_DB_REGKEY, m_objRegKeyDB, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 5)
	{
		//CFSDB objDelta;
		CMaxNewPESig objDelta;
		bMergeSuccess = MergeBalBSTOptDB(SD_DB_FS_BLK, m_objBlackDBManager, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 6)
	{
		CFSDB objDelta;

		bMergeSuccess = MergeBalBSTOptDB(SD_DB_FS_WHT, m_objPESigW, objDelta) ? bMergeSuccess : false;
		
		bMergeSuccess = MergeBalBSTOptDB(SD_DB_FS_QIK, m_objPESigQ, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 7)
	{
		bMergeSuccess = MergeRegFixDB() ? bMergeSuccess : false;
	}
	else if(lType == 8)
	{
		CUUSSU objDelta(false);
		bMergeSuccess = MergeBalBSTDB(SD_DB_REGVAL, m_objRegValDB, objDelta) ? bMergeSuccess : false;
	}
	else if(lType == 9)
	{
		CS2S objDelta(false);
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_REPAIR, m_objVirusR, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_PE_SIG, m_objVirusSPE, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_DOS_SIG, m_objVirusSDos, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_COM_SIG, m_objVirusSCom, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_WMA_SIG, m_objVirusSWMA, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_SCRIPT_SIG, m_objVirusSSCRIPT, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_OLE_SIG, m_objVirusSOLE, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_INF_SIG, m_objVirusSINF, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_PDF_SIG, m_objVirusSPDF, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_SIS_SIG, m_objVirusSSIS, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_DEX_SIG, m_objVirusSDEX, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_RTF_SIG, m_objVirusSRTF, objDelta) ? bMergeSuccess : false;
		bMergeSuccess = MergeBalBSTDB(VIRUS_DB_CURSOR_SIG, m_objVirusSCURSOR, objDelta) ? bMergeSuccess : false;

		CopyFile(m_csDeltaFileName + L"\\" + SD_DB_DEFINITIONCOUNT, m_csMergeTempDataFolder +  SD_DB_DEFINITIONCOUNT, false);
	}
	else if(lType == 10)
	{
		if((CSystemInfo::m_csProductNumber == L"18") && (bMergeFirewallDB || CSystemInfo::m_bIsFirewallInstalled))
		{
			CBufferToStructure objDelta(false, sizeof(DWORD), sizeof(URLDATA), sizeof(DWORD));
			bMergeSuccess = MergeBalBSTOptFWDB(SD_DB_ANTI_BANNER, m_objAntiBanner, objDelta) ? bMergeSuccess : false;
		}
		else
		{
			bMergeSuccess = true;
		}
	}
	else if(lType == 11)
	{
		if((CSystemInfo::m_csProductNumber == L"18") && (bMergeFirewallDB  || CSystemInfo::m_bIsFirewallInstalled))
		{
			CBufferToStructure objDelta(false, sizeof(DWORD), sizeof(URLDATA), sizeof(DWORD));
			bMergeSuccess = MergeBalBSTOptFWDB(SD_DB_ANTI_PHISHING, m_objAntiPhishing, objDelta) ? bMergeSuccess : false;
		}
		else
		{
			bMergeSuccess = true;
		}
	}
	else if(lType == 12)
	{
		CFSDB objDelta;
		bMergeSuccess = MergeBalBSTOptDB(SD_DB_FS_FULLFILE_MD5, m_objPESigFFS, objDelta) ? bMergeSuccess : false;		
	}
	return bMergeSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : ExtractDeltaFile
In Parameters  : CString csDeltaFileName, 
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::ExtractDeltaFile(const CString &csDeltaFileName)
{
	DeleteFile(csDeltaFileName + _T("a"));
	if(CBackupOperations::CopyAndEncryptFile(csDeltaFileName, csDeltaFileName + _T("a")))
	{
		m_oDirectoryManager.MaxDeleteDirectory(csDeltaFileName + _T("e"), true);
		if(CBackupOperations::ExtractFile(csDeltaFileName + _T("a"), csDeltaFileName + _T("e")))
		{
			DeleteFile(csDeltaFileName + _T("a"));
			m_csDeltaFileName = csDeltaFileName + _T("e");
			return true;
		}
		else
		{
			m_oDirectoryManager.MaxDeleteDirectory(csDeltaFileName + _T("e"), true);
		}
	}
	else
	{
		DeleteFile(csDeltaFileName + _T("a"));
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : ExtractDeltaFile
In Parameters  : CString csDeltaFileName, 
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CUpdateManager::ExtractDeltaFileEx(const CString &csDeltaFileName)
{
	m_csDeltaFileName = csDeltaFileName + _T("e");
	
	return true;
}

CString CUpdateManager::GetDeltaVersion(const CString &csFileName)
{
	try
	{
		CString csDeltaVerNo = csFileName;
		//csDeltaVerNo.Replace(_T("SDDatabase"), _T(""));			12-April-2016 Delta changes: Ravi
		csDeltaVerNo.Replace(_T("SDDatabaseDB"), _T(""));
		csDeltaVerNo.Replace(_T(".db"), _T(""));
		csDeltaVerNo.Insert(2, _T("."));
		csDeltaVerNo.Insert(4, _T("."));
		csDeltaVerNo.Insert(6, _T("."));
		return csDeltaVerNo;
	}
	catch(...)
	{
		AddLogEntry(L"Error occoured in CUpdateManager::GetDeltaVersion");
	}
	return BLANKSTRING;
}

bool CUpdateManager::ResetAllMembers()
{
	m_objNameDBMap.RemoveAll();
	m_objFileDB.RemoveAll();
	m_objFolderDB.RemoveAll();
	m_objCookieDB.RemoveAll();
	m_objRegKeyDB.RemoveAll();
	//m_objPESigB.RemoveAll();
	m_objPESigFFS.RemoveAll();
	m_objBlackDBManager.RemoveAll();
	m_objPESigW.RemoveAll();
	m_objPESigQ.RemoveAll();
	m_objRegFix.RemoveAll();
	m_objRegValDB.RemoveAll();
	m_objVirusR.RemoveAll();
	m_objVirusSPE.RemoveAll();
	m_objVirusSDos.RemoveAll();
	m_objVirusSCom.RemoveAll();
	m_objVirusSWMA.RemoveAll();
	m_objVirusSSCRIPT.RemoveAll();
	m_objVirusSOLE.RemoveAll();
	m_objVirusSINF.RemoveAll();
	m_objVirusSPDF.RemoveAll();
	m_objVirusSSIS.RemoveAll();
	m_objVirusSDEX.RemoveAll();
	m_objAntiBanner.RemoveAll();
	m_objAntiPhishing.RemoveAll();
	return true;
}

void CUpdateManager::AddFileNameToFailedList(CString * pcsList, CString csFileName)
{
	if(pcsList)
	{
		if(!((*pcsList).IsEmpty()))
		{
			(*pcsList) += _T(";");
			(*pcsList) += csFileName;
		}
		else
		{
			(*pcsList) = csFileName;
		}
	}
}
