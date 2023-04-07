/*=============================================================================
   FILE		           : FileOperation.h
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
#include <string>
#include <fstream>

using namespace std;
class CFileOperation
{
public:
	CFileOperation();
	virtual ~CFileOperation();

	static bool DeleteThisFile(CString csFilePath);
	static bool DeleteFolderTree(CString csFilePath,bool bSubDir, bool bDelPath, DWORD &dwLastError,CString csIgnoreFolder = _T(""),CString csIgnoreFolder1 = _T(""),CString csIgnoreFile = _T(""), bool bAddRestartDelete = false);
	static bool DeleteFolderTree(CString csFilePath, bool bSubDir, CString csIgnoreFolder,CString csIgnoreLogFolder);
	static bool ReplaceFileOnRestart(TCHAR const * szExistingFileName, TCHAR const * szNewFileName);

	bool MatchFilename(TCHAR const * FileName, TCHAR const * DBFileName);
	bool match(TCHAR const * w, TCHAR const * s);
};
