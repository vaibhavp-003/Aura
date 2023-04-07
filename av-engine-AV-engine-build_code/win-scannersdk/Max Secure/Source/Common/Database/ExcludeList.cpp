/*======================================================================================
   FILE				: ExcludeList.Cpp
   ABSTRACT			: List Of Spywares, Which User Doesn’t Want To Get Searched Or Removed 
					  While Searching The Spywares. Recovery Of The Exlcudeded Spywares
   DOCUMENTS		: SpyEliminator-LLD.Doc
   AUTHOR			: Nilesh Dorge
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/
#include "stdafx.h"
#include <direct.h>
#include "ExcludeList.h"
#include "SDSystemInfo.h"
#include "FileOperation.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CExcludeList
In Parameters  : bool bReadOnly,
Out Parameters :
Description    : C'tor..Reads the exclude list
Author         :
--------------------------------------------------------------------------------------*/
CExcludeList::CExcludeList(bool bReadOnly):m_bReadOnly(bReadOnly)
{
	this->Read();
}

/*--------------------------------------------------------------------------------------
Function       : ~CExcludeList
In Parameters  :
Out Parameters :
Description    : D'tor - Saves the Exclude list
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CExcludeList::~CExcludeList()
{
	if(!m_bReadOnly)
		this->Save();
}

/*-------------------------------------------------------------------------------------
Function		: GetFileName
In Parameters	: Void
Out Parameters	: CString : Return The Database File Name
Purpose			: To Get The Exclude Database File Name
Author			: Nilesh Dorge
--------------------------------------------------------------------------------------*/
CString CExcludeList::GetFileName()const
{
	CString csPath = CSystemInfo::m_strDBPath + _T("\\") + EXCLUDE_SPYDB_FILE_NAME;

	//To Set The File Attribute To ARCHIVE
	SetFileAttributes(csPath,FILE_ATTRIBUTE_ARCHIVE);
	return (csPath);
}

/*-------------------------------------------------------------------------------------
Function		: Read
In Parameters	: void
Out Parameters	: bool: true if SUCCESS else false
Purpose			: To Read The Data From Excluded Database File
Author			: Nilesh Dorge
--------------------------------------------------------------------------------------*/
void CExcludeList::Read(void)
{
	try
	{
		CFile theFile;
		CFileException ex;

		//To solve mem.leak problem.
		CString strFileName;
		strFileName = this->GetFileName();
		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeRead,&ex))
		{
			strFileName.ReleaseBuffer();
			return;
		}
		strFileName.ReleaseBuffer();
		CArchive archive(&theFile, CArchive::load);
		//serilize the Map
		this->Serialize(archive);

		//To Close The Handles
		archive.Close();
		theFile.Close();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception Caught in CExcludeList::Read"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: Save
In Parameters	: void
Out Parameters	: bool: true if SUCCESS else false
Purpose			: To Save The Data From Excluded Database File
Author			: Nilesh Dorge
--------------------------------------------------------------------------------------*/
void CExcludeList::Save(void)
{
	try
	{
		CFile theFile;
		CFileException ex;
		CString strFileName;
		strFileName = this->GetFileName();
		//sandip added to remove crash if not open file 11/03/2008
		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeCreate | CFile::modeWrite, &ex))
		{
			strFileName.ReleaseBuffer();
			return;
		}
		strFileName.ReleaseBuffer();
		CArchive archive(&theFile, CArchive::store);

		//serilize the Map
		this->Serialize(archive);

		//To Close The Handles
		archive.Close();
		theFile.Close();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception Caught in CExcludeList::Save"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: Read
In Parameters	: void
Out Parameters	: void
Purpose			: To Remove The Data From Excluded Database File
To Remove The Spyware From Exclude List...After This Destructor
Will Get Call Which..Then Save The Updated Spyware List In The File
Author			: Nilesh Dorge
--------------------------------------------------------------------------------------*/
void CExcludeList::Remove(const CString & spyName)
{
	for (int i = 0; i < static_cast<int>(this->GetCount()); i++)
	{
		if(spyName == this->GetAt(i))
		{
			this->RemoveAt(i);
		}
	}
}
