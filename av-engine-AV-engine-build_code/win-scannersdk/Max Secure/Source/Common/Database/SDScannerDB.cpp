/*======================================================================================
FILE             : SDScannerDB.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 14 March, 2009.
NOTES		     : Stores the Scan Statistics in a DB
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxConstant.h"
#include "SDScannerDB.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CSDScannerDB
In Parameters  : void,
Out Parameters :
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CSDScannerDB::CSDScannerDB(void):m_objScanDB(false)
{
	m_iHighCount = 0;
	m_iMediumCount = 0;
	m_iCriticalCount = 0;
	m_iLowCount  = 0;
}

/*--------------------------------------------------------------------------------------
Function       : ~CSDScannerDB
In Parameters  : void,
Out Parameters :
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CSDScannerDB::~CSDScannerDB(void)
{

}

/*--------------------------------------------------------------------------------------
Function       : ReadScanDBFile
In Parameters  :
Out Parameters : bool
Description    : Loading the Scan DB file
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CSDScannerDB::ReadScanDBFile()
{
	CString strFileName;
	strFileName.Format(_T("%s%s"), CSystemInfo::m_strAppPath, HEURISTIC_DATABASE);
	return m_objScanDB.Load(strFileName);
}

/*--------------------------------------------------------------------------------------
Function       : FindWormInScanDB
In Parameters  : const CString &csPath,
Out Parameters : bool
Description    : Perform serach on the DB
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CSDScannerDB::FindWormInScanDB(const CString &csPath)
{
	CString csTempPath(csPath);
	csTempPath.MakeLower();
	return m_objScanDB.SearchItem(csTempPath, NULL);
}

/*--------------------------------------------------------------------------------------
Function       : RemoveWormFromScanDB
In Parameters  : const CString & csPath,
Out Parameters : bool
Description    : Delete Item from Scanner DB
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CSDScannerDB::RemoveWormFromScanDB(const CString & csPath)
{
	CString csTempPath(csPath);
	csTempPath.MakeLower();
	return m_objScanDB.DeleteItem(csTempPath);
}

/*--------------------------------------------------------------------------------------
Function       : SaveScanDBFile
In Parameters  :
Out Parameters : bool
Description    : Save the updated Scan DB file
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CSDScannerDB::SaveScanDBFile()
{
	CString strFileName;

	if(!m_objScanDB.GetFirst())
	{
		return false;
	}
	else
	{
		strFileName.Format(_T("%s%s"), CSystemInfo::m_strAppPath, HEURISTIC_DATABASE);
		m_objScanDB.Balance();
		return m_objScanDB.Save(strFileName);
	}
}

/*--------------------------------------------------------------------------------------
Function       : AddEntryinScanDB
In Parameters  : const CString &csWorm,
Out Parameters : void
Description    : Adding Entry in Scan DB
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CSDScannerDB::AddEntryinScanDB(const CString &csWorm, DWORD dwSpyID)
{
	CString csTempPath(csWorm);
	csTempPath.MakeLower();
	m_objScanDB.AppendItem(csTempPath,dwSpyID);
}

/*--------------------------------------------------------------------------------------
Function       : IsScanDBLoaded
In Parameters  : 
Out Parameters : bool
Description    : check if scan db loaded
Author         : Anand
--------------------------------------------------------------------------------------*/
bool CSDScannerDB::IsScanDBLoaded()
{
	return NULL != m_objScanDB.GetFirst();
}

/*--------------------------------------------------------------------------------------
Function       : UnLoadScanDB
In Parameters  : 
Out Parameters : 
Description    : unload scan db
Author         : Anand
--------------------------------------------------------------------------------------*/
void CSDScannerDB::UnLoadScanDB()
{
	m_objScanDB.RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : AddEntryinGraphINI
In Parameters  : const int &threatIndex,
Out Parameters : void
Description    : Adding entry in INI file
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CSDScannerDB::AddEntryinGraphINI(const int &threatIndex)
{
	if(threatIndex == ENUM_TI_LOW)
	{
		m_iLowCount++;
	}
	if(threatIndex == ENUM_TI_MEDIUM)
	{
		m_iMediumCount++;
	}
	else if(threatIndex == ENUM_TI_HIGH)
	{
		m_iHighCount++;
	}
	else if(threatIndex == ENUM_TI_CRITICAL)
	{
		m_iCriticalCount++;
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetStringFromINI
In Parameters  : const CString& csINIHeader, const CString& csINISection,
Out Parameters : CString
Description    : Retrieves the Strings from INI file
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CString CSDScannerDB::GetStringFromINI(const CString& csINIHeader, const CString& csINISection)
{
	CString csReadValue;
	GetPrivateProfileString(csINIHeader, csINISection, _T(""), csReadValue.GetBuffer(MAX_PATH), MAX_PATH, m_csINIFilePath);
	csReadValue.ReleaseBuffer();
	csReadValue.MakeUpper();
	return csReadValue;
}

/*--------------------------------------------------------------------------------------
Function       : WriteCountInINI
In Parameters  :
Out Parameters : bool
Description    : Updating the Scan Count in INI
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CSDScannerDB::WriteCountInINI()
{
	CString csReadValue;
	CString csCount;
	m_csINIFilePath = CSystemInfo::m_strAppPath+_T("\\Setting\\wormcounts.ini");
	CString csINIHeader = _T("ThreatLevel");

	csCount = GetStringFromINI(csINIHeader, _T("Low"));
	m_iLowCount +=_wtoi(csCount);
	csReadValue.Format(_T("%d"),m_iLowCount);
	WritePrivateProfileString(csINIHeader, _T("Low"), csReadValue, m_csINIFilePath);

	csCount = GetStringFromINI(csINIHeader, _T("Medium"));
	m_iMediumCount +=_wtoi(csCount);
	csReadValue.Format(_T("%d"),m_iMediumCount);
	WritePrivateProfileString(csINIHeader, _T("Medium"), csReadValue, m_csINIFilePath);

	csCount = GetStringFromINI(csINIHeader, _T("High"));
	m_iHighCount +=_wtoi(csCount);
	csReadValue.Format(_T("%d"),m_iHighCount);
	WritePrivateProfileString(csINIHeader, _T("High"), csReadValue, m_csINIFilePath);

	csCount = GetStringFromINI(csINIHeader, _T("Critical"));
	m_iCriticalCount +=_wtoi(csCount);
	csReadValue.Format(_T("%d"),m_iCriticalCount);
	WritePrivateProfileString(csINIHeader, _T("Critical"), csReadValue, m_csINIFilePath);

	m_iHighCount = 0;
	m_iMediumCount = 0;
	m_iCriticalCount = 0;
	m_iLowCount  = 0;
	return true;
}
