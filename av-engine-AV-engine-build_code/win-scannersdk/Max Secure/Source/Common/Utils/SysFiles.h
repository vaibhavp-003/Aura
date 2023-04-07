/*======================================================================================
FILE             : SysFiles.h
ABSTRACT         : defines a class which checks for scanned system files and replaces from fresh
DOCUMENTS	     : 
AUTHOR		     : Yuvraj
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
				  
CREATION DATE    : 
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "MaxConstant.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include "U2OU2O.h"
#include "DBPathExpander.h"

bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

class CSysFiles
{
public:

	CSysFiles(void);
	~CSysFiles(void);

	bool LoadSysDB(const CString &csMaxDBPath);
	bool CheckSystemFile(SD_Message_Info eScnrType, LPCTSTR szFilePath, LPTSTR szReplacePath, SIZE_T cchReplacePath);
	bool UnloadSysDB();

private:

	int				m_iLoadTries;
	bool			m_bDBLoaded;
	CU2OU2O			m_objSysFilesDB;
	CRegistry		m_objRegistry;
	CDBPathExpander	m_ojbDBPathExpander;
	bool m_bSysWow;
	bool m_bDrvFile;
	bool m_bIs64OS;

	bool IsFilePresentInDB(LPCTSTR szFilePath);
	bool FindFreshCopy(LPCTSTR szFilePath, LPTSTR szReplacePath, SIZE_T cchReplacePath);
	bool AreFilesDifferent(LPCTSTR szFilePath1, LPCTSTR szFilePath2);
	bool GetReplaceFileFrom(CString csHoldFileName, LPCTSTR szFilter, LPCTSTR szOriFileName, LPCTSTR szOrigFullFilePath, LPTSTR szReplacePath, SIZE_T cchReplacePath);
};