/*======================================================================================
FILE             : FileOperations.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
-------------------Created as an unpublished copyright work.  All rights reserved.
-------------------This document and the information it contains is confidential and
-------------------proprietary to Aura.  Hence, it may not be
-------------------used, copied, reproduced, transmitted, or stored in any form or by any
-------------------means, electronic, recording, photocopying, mechanical or otherwise,
-------------------without the prior written permission of Aura.
CREATION DATE   : 8/1/2009 7:55:44 PM
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#pragma once

class CFileOperations
{
public:
	CFileOperations();
	virtual ~CFileOperations();

	bool ProcessDatabase(LPCWSTR lstrFileName, CObject &objDatabaseMap, bool bSave);
	BOOL ParseInfo(CString);

private:

	void CryptData(DWORD * Data, DWORD dwDataSize, char * key = 0, unsigned long keylen = 0);
	bool CryptFile(const TCHAR * csFileName, const TCHAR * csCryptFileName);
	void GetOSVersion(LPTSTR pszOS);
};