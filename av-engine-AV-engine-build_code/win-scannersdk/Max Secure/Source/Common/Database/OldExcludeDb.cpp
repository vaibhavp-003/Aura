/*======================================================================================
   FILE				: ExcludeDb.Cpp
   ABSTRACT			: List Of Spywares, Which User Doesn’t Want To Get Searched Or Removed 
					  While Searching The Spywares. Recovery Of The Exlcudeded Spywares
   DOCUMENTS		: OptionDll Design.doc
   AUTHOR			: Dipali
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 5/May/2008
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/
#include "pch.h"
#include "OldExcludeDb.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : COldExcludeDb
In Parameters  : void,
Out Parameters :
Description    : C'tor
Author         :
--------------------------------------------------------------------------------------*/
COldExcludeDb::COldExcludeDb(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~COldExcludeDb
In Parameters  : void,
Out Parameters :
Description    : D'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
COldExcludeDb::~COldExcludeDb(void)
{
	m_objExcludeDb.RemoveAll();
	DeleteFile(GetFileName());
}

/*-------------------------------------------------------------------------------------
Function		: GetFileName
In Parameters	: Void
Out Parameters	: CString : Return The Database File Name
Purpose			: To Get The Exclude Database File Name
Author			: Dipali
--------------------------------------------------------------------------------------*/
CString COldExcludeDb::GetFileName()const
{
	CString csPath = CSystemInfo::m_strDBPath + _T("\\") + _T("Exclude.db");
	//To Set The File Attribute To ARCHIVE
	SetFileAttributes(csPath, FILE_ATTRIBUTE_ARCHIVE);
	return (csPath);
}

/*-------------------------------------------------------------------------------------
Function		: Read
In Parameters	: void
Out Parameters	: bool: true if SUCCESS else false
Purpose			: To Read The Data From Excluded Database File
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool COldExcludeDb::Read(void)
{
	CString strFileName = GetFileName();
	bool bRet = false;
	try
	{
		CFile theFile;
		CFileException ex;
		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeRead, &ex))
		{
			strFileName.ReleaseBuffer();
			bRet = false;
		}
		else
		{
			bRet = true;
			strFileName.ReleaseBuffer();
			CArchive archive(&theFile, CArchive::load);

			//serilize the Map
			m_objExcludeDb.Serialize(archive);
			archive.Close();
			theFile.Close();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("##### Exception caught while loading DB: %s"), strFileName, 0);
		bRet = false;
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: Save
In Parameters	: Void
Out Parameters	: bool: true if SUCCESS else false
Purpose			: To Save The Data From Excluded Database File
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool COldExcludeDb::Save(void)
{
	try
	{
		CFile theFile;
		CFileException ex;
		CString strFileName;
		strFileName = this->GetFileName();

		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeCreate | CFile::modeWrite, &ex))
		{
			strFileName.ReleaseBuffer();
			return false;
		}
		strFileName.ReleaseBuffer();
		CArchive archive(&theFile, CArchive::store);

		//serilize the Map
		m_objExcludeDb.Serialize(archive);

		//To Close The Handles
		archive.Close();
		theFile.Close();
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception Caught in COldExcludeDb::Save"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Exclude
In Parameters	: CString &csName - Spyware Name
CString &csSpyware - Spyware value
bool bParent - Exclude all / single entry
Out Parameters	: void
Purpose			: Exclude given entry
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void COldExcludeDb::Exclude(CString &csName, CString &csSpyware, bool bParent)
{
	csName.MakeLower();
	csSpyware.MakeLower();
	POSITION pos = m_objExcludeDb.Find(csName);
	if(pos)// already exlcuded some entires
	{
		CtStringToULong *pSpywareNameList = NULL;
		pSpywareNameList = (CtStringToULong *)m_objExcludeDb.GetData(pos);
		if(pSpywareNameList!= NULL)
		{
			if(bParent)
			{
				pSpywareNameList->RemoveAll();
				pSpywareNameList = NULL;
				m_objExcludeDb.SetData(pos,(CObject *)pSpywareNameList);
			}
			else
				pSpywareNameList->Set(csSpyware,1);
		}
	}
	else
	{
		if(!bParent && csSpyware != _T(""))
		{
			CtStringToULong *pSpywareNameList = new CtStringToULong;
			if(pSpywareNameList!= NULL)
			{
				pSpywareNameList->Set(csSpyware,1);
				m_objExcludeDb.Set(csName, (CObject *)pSpywareNameList);
			}
		}
		else
		{
			CtStringToULong *pSpywareNameList = NULL;
			m_objExcludeDb.Set(csName, (CObject *)pSpywareNameList);
		}
	}
	return;
}

/*-------------------------------------------------------------------------------------
Function		: IsExcluded
In Parameters	: CString &csName - Spyware Name
CString &csSpyware - Spyware value
bool bParent - Exclude all / single entry
Out Parameters	: void
Purpose			: check given spyware name/value is in exclude list
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool COldExcludeDb::IsExcluded(CString csName, CString &csSpyware, bool bParent)
{
	csName.MakeLower();
	csSpyware.MakeLower();
	POSITION pos = m_objExcludeDb.Find(csName);
	if(pos)
	{
		CtStringToULong *pSpywareNameList = NULL;
		pSpywareNameList = (CtStringToULong *)m_objExcludeDb.GetData(pos);
		if(bParent)
		{
			if(pSpywareNameList == NULL)
				return true;
			else
				return false;
		}
		else
		{
			if(pSpywareNameList!= NULL)
			{
				//check spyware value in exclude db
				pos = pSpywareNameList->Find(csSpyware);
				if(pos)
					return true;
				else
					return false;
			}
			else
			{
				// if this object is null means exclude spyware by name
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Recover
In Parameters	: CString &csName - Spyware Name
CString &csSpyware - Spyware value
bool bParent - Exclude all / single entry
Out Parameters	: void
Purpose			: recover given spyware name/value is in exclude list
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void COldExcludeDb::Recover(CString &csName, CString &csSpyware, bool bParent)
{
	csName.MakeLower();
	csSpyware.MakeLower();
	POSITION pos = m_objExcludeDb.Find(csName);
	if(pos)
	{
		if(bParent)//recover all
		{
			m_objExcludeDb.Remove(pos);
		}
		else//recover only one entry
		{
			CtStringToULong *pSpywareNameList = NULL;
			pSpywareNameList = (CtStringToULong *)m_objExcludeDb.GetData(pos);
			if(pSpywareNameList!= NULL)
			{
				POSITION pos1 = pSpywareNameList->Find(csSpyware);
				if(pos1)
				{
					pSpywareNameList->Remove(pos1);
					//if last entry remove key also
					if(pSpywareNameList->GetCount() == 0)
					{
						m_objExcludeDb.Remove(pos);
					}
				}
			}

		}
	}
}