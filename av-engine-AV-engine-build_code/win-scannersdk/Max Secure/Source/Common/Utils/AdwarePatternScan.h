/*======================================================================================
   FILE				: AdwarePatternScan.h
   ABSTRACT			: Model responsible for Adware scanning 
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module searches and detects Adwares using Pattern and Rules
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxDeleteRegistryEntry.h"

class CAdwarePatternScan
{
public:

	CAdwarePatternScan();
	~CAdwarePatternScan();
	//TCHAR	szPathsPartName[MAX_PATH];
	bool ScanAdwarePattern(LPCTSTR szFilePath);

private:
	
	bool ScanPriceLess(LPCTSTR szFilePath); 
	bool ScanHardcodedPathAndFolderName(LPCTSTR szFilePath);
	bool ParseFilePath(LPCTSTR szParentFolderPath,LPTSTR szParentFolderName,int iDepth);
	bool Scan4AdwAmonetizeFolder(LPCTSTR szFilePath);
	bool Scan4AdwMultiplugbei(LPCTSTR szFilePath);
	bool CheckForFiles(LPCTSTR szFolderPath, LPCTSTR szFileName);
	bool Scan4ExeConfigPattern(LPCTSTR szFilePath);

	bool Scan4UpdEngine(LPCTSTR szFilePath);
	bool Scan4FolderPattern(LPCTSTR szFilePath);
	bool Scan4FOLDEREXENamePattern(LPCTSTR szFilePath);
	
	int	GetFolderDetails(LPCTSTR szFolPath);

	void TrimString(LPTSTR szString);

	bool ScanForMegaSearchExtension(LPCTSTR szFilePath);
	bool ParseFile(LPCTSTR szFilePath, TCHAR *pszFileName);
	bool CheckForMegaSearchFiles(LPCTSTR szFolderpath,LPCTSTR szFileNameToSearch);
	bool ScanForWebSearch(LPCTSTR szFilePath);
	bool CheckForWebSearchFiles(LPCTSTR szFolderPath);
	bool ScanCommonExtJS(LPCTSTR szFilePath,LPCTSTR szFileName,LPCTSTR szIllegalWebsite);
	bool ParseFileCommonJS(LPCTSTR szFilePath,LPCTSTR szIllegalWebsite);
	bool ScanAndParseCommon(LPCTSTR szFilePath);
	bool Scan4ISTempAndTempPattern(LPCTSTR szFilePath);

	bool ThreeFilePtrn(LPCTSTR szFilePath);
	bool CloudNetPtrn(LPCTSTR szFilePath);

	bool GoogleChromePtrn(LPCTSTR szFilePath);
};