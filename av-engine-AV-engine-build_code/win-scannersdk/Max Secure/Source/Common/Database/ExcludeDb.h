
/*======================================================================================
FILE             : ExcludeDb.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : 
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 5/15/2009.
NOTES		     : Declaration of CExcludeDB class used for exclusions while scanning
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "S2U.h"
#include "U2S.h"
#include "S2S.h"

class CExcludeDb
{
public:
	CExcludeDb(void);
	~CExcludeDb(void);

	void SetDatabasePath(LPCTSTR szPathWithSlash);
	bool ReLoadExcludeDB();
	void SaveExcludeDB();
	bool IsExcluded(ULONG &lSpyName, LPCTSTR strSpyName, LPCTSTR lpValue);
	bool IsFolderExcluded(LPCTSTR szFolder);
	bool Exclude(ULONG &lSpyName, LPCTSTR strSpyName, LPCTSTR lpValue);
	bool Recover(ULONG &lSpyName, LPCTSTR strSpyName, LPCTSTR lpValue);
	bool MergeDB(CExcludeDb& objNewDB);

	bool IsModified()
	{
		if(m_objExDBByID.IsModified())
			return true;

		if(m_objExDBByName.IsModified())
			return true;

		if(m_objExDBByEntryID.IsModified())
			return true;

		if(m_objExDBByEntryName.IsModified())
			return true;

		return false;
	}

	// exclude db files classes
	CU2S			m_objExDBByID;
	CS2U			m_objExDBByName;
	CS2U			m_objExDBByEntryID;
	CS2S			m_objExDBByEntryName;
	bool			m_bNewNodeAdded;
	CString			m_csDatabasePath;
	CS2U			m_objExDBAutoRtkt;
};
