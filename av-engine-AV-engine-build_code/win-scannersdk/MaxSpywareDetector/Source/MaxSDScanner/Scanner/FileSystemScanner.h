/*======================================================================================
FILE             : FileSystemScanner.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
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
				  
CREATION DATE    : 8/1/2009 6:56:22 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "FileSystemBase.h"

class CFileSystemScanner : public CFileSystemBase
{
public:
	CFileSystemScanner(void);
	~CFileSystemScanner(void);

	CString m_csDrivesToScan;
	void GetTotalScanningSize();
	/*void SetParams(bool bMacLearning = false);*/
	//void ScanSystem(const TCHAR *strDrivesToScan, bool bSignatureScan, CS2U* pobjFilesList,
	//				CS2U* pobjFoldersList, bool bScanReferences, bool bVirusScan);
	void ScanSystem(const TCHAR *strDrivesToScan, bool bSignatureScan, CS2U* pobjFilesList,
					CS2U* pobjFoldersList, bool bScanReferences, bool bVirusScan, bool bUsbScan = false, bool bMachineLearning = false);
	void ScanSystemWithSignature(const TCHAR *strDrivesToScan, bool bVirusScan, bool bDeepScan, bool bDatabaseScan, bool bUSBScan);
	void ScanSystemWithSignatureSEH(const TCHAR *strDrivesToScan, bool bVirusScan, bool bDeepScan, bool bDatabaseScan, bool bUSBScan = false);
};
