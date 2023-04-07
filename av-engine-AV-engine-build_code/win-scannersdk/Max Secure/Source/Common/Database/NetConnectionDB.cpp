/*======================================================================================
   FILE				: NetConnectionDB.Cpp
   ABSTRACT			: IP address database file. IP --> ipinfo abject (CIPInfo)
   DOCUMENTS		: Network Connection scanner-Design Document.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 10/june/2008
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/

#include "stdafx.h"
#include "NetConnectionDB.h"
#include "FileOperation.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
//TODO:Darshit Once the DB and Scanner is implemented
//
#ifdef SCANNER
CNetConnectionDB::CNetConnectionDB()
{

}

CNetConnectionDB::~CNetConnectionDB(void)
{
	m_objNetCondb.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Save
	In Parameters	: CString strFileName - file name
	Out Parameters	: void
	Purpose			: Save ip database file
	Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CNetConnectionDB::Save(CString &strFileName)
{
	try
	{
		CFile theFile;
		CFileException ex;

		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeCreate | CFile::modeWrite, &ex))
		{
			strFileName.ReleaseBuffer();
			return;
		}

		strFileName.ReleaseBuffer();
		CArchive archive(&theFile, CArchive::store);

		//serilize the Map
		m_objNetCondb.Serialize(archive);

		archive.Close();
		theFile.Close();
	}
	catch( ... )
	{
		AddLogEntry(_T("##### Exception caught while saving DB: %s"), strFileName, 0);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: Read
	In Parameters	: CString strFileName - file name
	Out Parameters	: void
	Purpose			: Read IP database file
	Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CNetConnectionDB::Read(CString &strFileName)
{
	CFile theFile;
	try
	{
		CFileException ex;

		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeRead, &ex))
		{
			strFileName.ReleaseBuffer();
			return;
		}
		strFileName.ReleaseBuffer();
		CArchive archive(&theFile, CArchive::load);

		//serilize the Map
		m_objNetCondb.Serialize( archive );

		archive.Close();
		theFile.Close();	
	}

	catch( ... )
	{
		AddLogEntry(_T("##### Exception caught while loading DB: %s"), strFileName, 0);
		theFile.Close();
	}
}

/*-------------------------------------------------------------------------------------
	Function		: Read
	In Parameters	: CString strFileName - file name
					  CObject &objNameToWorm - db object
	Out Parameters	: void
	Purpose			: Read IP database file
	Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CNetConnectionDB::Read(CString &strFileName, CObject &objNameToWorm)
{
	CFile theFile;
	try
	{
		CFileException ex;

		if(!theFile.Open(strFileName.GetBuffer(), CFile::modeRead, &ex))
		{
			strFileName.ReleaseBuffer();
			return;
		}
		strFileName.ReleaseBuffer();
		CArchive archive(&theFile, CArchive::load);

		//serilize the Map
		objNameToWorm.Serialize( archive );

		archive.Close();
		theFile.Close();	
	}

	catch( ... )
	{
		AddLogEntry(_T("##### Exception caught while loading DB: %s"), strFileName, 0);
		theFile.Close();
	}
}
#endif