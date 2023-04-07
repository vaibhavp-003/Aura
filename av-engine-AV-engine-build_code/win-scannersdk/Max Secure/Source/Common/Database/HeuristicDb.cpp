/*======================================================================================
   FILE			: HeuristicDb.cpp 
   ABSTRACT		: class for handling operation realted to local Heuristic db
   DOCUMENTS	: Heuristics_LocalDb Design document.DOC
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 15-May-2008
   NOTES		:
   VERSION HISTORY	:
 ======================================================================================*/

#include "stdafx.h"
#include "HeuristicDb.h"
#include "HeuristicFileInfo.h"
#include "HardDiskManager.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CHeuristicDb::CHeuristicDb(void)
{
	m_bChanged = false;

}

CHeuristicDb::~CHeuristicDb(void)
{
	//remove the map
	m_objLocaldb.RemoveAll();
}

/*-------------------------------------------------------------------------------------
Function		: Save
In Parameters	: CString csDrv - drive letter
Out Parameters	: void
Purpose			: Save the local DB
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CHeuristicDb::Save(const CString& strFileName)
{
	try
	{
		CHardDiskManager objHDDManager;
		objHDDManager.CheckFreeSpace(strFileName.Left(strFileName.Find(_T("\\"))));
		if(objHDDManager.GetTotalNumberOfFreeGBytes() == 0)
		{
			AddLogEntry(_T("Disk full, Drive: ") + strFileName.Left(strFileName.Find(_T("\\"))));
			return;
		}

		CFile theFile;
		CFileException ex;

		SetFileAttributes(strFileName, FILE_ATTRIBUTE_NORMAL);
		if(!theFile.Open(strFileName, CFile::modeCreate | CFile::modeWrite, &ex))
		{
			return;
		}
		CArchive archive(&theFile, CArchive::store);

		//serilize the Map
		m_objLocaldb.Serialize(archive);

		archive.Close();
		theFile.Close();
		//Hide our database
		SetFileAttributes(strFileName, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
	}
	catch(...)
	{
		AddLogEntry(_T("##### Exception caught while saving DB: %s"), strFileName, 0);
	}
}

/*-------------------------------------------------------------------------------------
Function		: Read
In Parameters	: CString csDrv - drive letter
Out Parameters	: void
Purpose			: Read the local DB
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CHeuristicDb::Read(const CString& strFileName)
{
	CFile theFile;
	try
	{
		CFileException ex;
		SetFileAttributes(strFileName, FILE_ATTRIBUTE_NORMAL);

		if(!theFile.Open(strFileName, CFile::modeRead, &ex))
		{
			return;
		}
		CArchive archive(&theFile, CArchive::load);

		//serilize the Map
		m_objLocaldb.Serialize(archive);

		archive.Close();
		theFile.Close();

		//Hide our database
		SetFileAttributes(strFileName, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
	}
	catch(...)
	{
		AddLogEntry(_T("##### Exception caught while loading DB: %s"), strFileName, 0);
		AddLogEntry(_T("CHeuristicDb::Read(const CString& strFileName)"));
		theFile.Close();
		DeleteFile(strFileName);
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetHeuristicInfo
In Parameters	: const CString, CString, DWORD, DWORD, int
Out Parameters	: void
Purpose			: This will create crc64 of filename and search entry in the local
database.If entry found, it will check for the date and size,
if any one is different then return blank otherwise return
heuristic info and threat weight.If entry not found return blank..
If Heuristic info is blank then recreate the heuristic pattern.
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CHeuristicDb::GetHeuristicInfo(const CString& csFileName, CString &csHeuristicPattern, double &iTotalWeight, DWORD nModifiedTimeHigh, DWORD nModifiedTimeLow, ULONGLONG ulSize)
{
	CStringA csVal = "";
	m_objCRC64.GetCRC64((CStringA)csFileName, csVal);

	POSITION posSignature = m_objLocaldb.Find((CString)csVal);
	if(!posSignature)
	{
		csHeuristicPattern = BLANKSTRING; // pattern not found in our local database!Re-Generate!
		return;
	}

	CHeuristicFileInfo *pFileObj = (CHeuristicFileInfo*)m_objLocaldb.GetData(posSignature);
	if(pFileObj != NULL)
	{
		//if date time is different, re-generate signature
		if((pFileObj->m_csHeuristicPattern == BLANKSTRING) || (pFileObj->m_dwHighDateTime != nModifiedTimeHigh) || (pFileObj->m_dwLowDateTime != nModifiedTimeLow || pFileObj->m_ulSize != ulSize))
		{
			csHeuristicPattern = BLANKSTRING;						// pattern is old or not present!Re-Generate!
			return;
		}
		iTotalWeight = pFileObj->m_dTotalWeight;
		csHeuristicPattern = pFileObj->m_csHeuristicPattern;		// pattern found for the given file!
	}
	else
		csHeuristicPattern = BLANKSTRING;  // pattern is old or not present!Re-Generate!
}


/*-------------------------------------------------------------------------------------
Function		: SetHeuristicInfo
In Parameters	: const CString, CString, DWORD, DWORD, int
Out Parameters	: bool
Purpose			: Saves Heuristic pattern in Local DB.
Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CHeuristicDb::SetHeuristicInfo(const CString& csFileName, CString csHeuristicPattern, double iTotalWeight, DWORD nModifiedTimeHigh, DWORD nModifiedTimeLow, ULONGLONG ulSize)
{
	CStringA csCRCFile = "";
	m_objCRC64.GetCRC64((CStringA)csFileName, csCRCFile);

	POSITION pos = m_objLocaldb.Find((CString)csCRCFile);
	if(!pos)
	{
		CHeuristicFileInfo *pFileInfoObj = new CHeuristicFileInfo();
		pFileInfoObj->m_csHeuristicPattern = csHeuristicPattern;
		pFileInfoObj->m_dwHighDateTime = nModifiedTimeHigh;
		pFileInfoObj->m_dwLowDateTime = nModifiedTimeLow;
		pFileInfoObj->m_ulSize	= ulSize;
		pFileInfoObj->m_dTotalWeight = iTotalWeight;
		m_objLocaldb.Set((CString)csCRCFile, (CObject*)pFileInfoObj);
		m_bChanged = true;
		return true;
	}
	else
	{

		CHeuristicFileInfo *pFileInfoObj = (CHeuristicFileInfo*)m_objLocaldb.GetData(pos);
		if(pFileInfoObj != NULL)
		{
			pFileInfoObj->m_csHeuristicPattern = csHeuristicPattern;
			pFileInfoObj->m_dwHighDateTime = nModifiedTimeHigh;
			pFileInfoObj->m_dwLowDateTime = nModifiedTimeLow;
			pFileInfoObj->m_ulSize	= ulSize;
			pFileInfoObj->m_dTotalWeight = iTotalWeight;
			m_bChanged = true;
			return true;
		}
	}
	return false;
}
