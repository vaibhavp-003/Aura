/*======================================================================================
FILE             : StartupScanner.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
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
				  
CREATION DATE    : 20/12/2010 8:14:24 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "ScannerBase.h"
#include "BSArray.h"
#include "VirusScannerBase.h"
#include "FileSig.h"
#include "FileSignatureDb.h"

class CStartupScanner : public CScannerBase
{
public:
	CStartupScanner(void);
	~CStartupScanner(void);

	bool ScanStartupFile(LPCTSTR szFilePath);
	void ScanStartupFiles(bool bDeepScan);
	bool IsScanningStopped();
	void SendStatusTOGUI(CString csFileName,INT_PTR iTotalEntries,INT_PTR iCounter);

private:
	bool EnumerateAllStartupFiles();
};
