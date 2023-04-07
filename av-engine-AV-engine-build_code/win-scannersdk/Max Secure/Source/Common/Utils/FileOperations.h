/*=============================================================================
   FILE		           : FileOperations.h
   ABSTRACT		       : This Class perform file / folder related opration
						like DeleteFolderTree,DeleteCache,GetSignature,QurantineBackup
   DOCUMENTS	       : Refer The System Design.doc, System Requirement Document.doc
   AUTHOR		       : Dipali Pawar
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 26-Jan-2006
   NOTES		      : This Class perform file / folder related opration
						like DeleteFolderTree,DeleteCache,GetSignature,QurantineBackup
   VERSION HISTORY    : 
=============================================================================*/
#pragma once

class CFileOperations
{
public:
	CFileOperations();
	virtual ~CFileOperations();
	bool ProcessDatabase(LPCWSTR lstrFileName, CObject &objDatabaseMap, bool bSave);

private:
	void CryptData(DWORD * Data, DWORD dwDataSize, char * key = 0, unsigned long keylen = 0);
	bool CryptFile(const TCHAR * csFileName, const TCHAR * csCryptFileName);
};