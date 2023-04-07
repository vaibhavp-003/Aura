/*======================================================================================
   FILE				: CommonFileIntegrityCheck.h
   ABSTRACT			: 
   DOCUMENTS		: 
   AUTHOR			: Sandip Sanap
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE      : 14-Nov-2009
   NOTES			: This class containts commaon functions needed for file integirty check.
   VERSION HISTORY	: 	
======================================================================================*/

#pragma once
#include "S2S.h"

typedef LRESULT (*MYPROC)(CStringA, CStringA&, bool);

class CCommonFileIntegrityCheck
{
public:
	CCommonFileIntegrityCheck(LPCTSTR szDBPath);
	~CCommonFileIntegrityCheck(void);

	bool ReadINIAndCreateDB(const TCHAR * szINIPath);
	bool CheckBinaryFileMD5(LPCTSTR szAppPath);
	TCHAR * GetSignature(TCHAR * csFilePath, TCHAR * szMd5);

private:
	CS2S m_objNameMD5Db;
	TCHAR m_szDBPath[MAX_PATH];
	bool m_bSave;

	bool CheckMD5(const TCHAR * szFilePath, const TCHAR * szMD5);
	bool DeleteDBFile(const TCHAR * szFilePath);
	bool AddFile(const TCHAR * szFilePath, const TCHAR * szMD5);
	BOOL VerifyEmbeddedSignature(LPCWSTR csAppPath);
};
