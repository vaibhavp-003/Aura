/*======================================================================================
FILE             : ProcessScanner.h
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
				  
CREATION DATE    : 8/1/2009 7:00:33 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "ScannerBase.h"

class CProcessScanner : public CScannerBase
{
public:
	CProcessScanner(void);
	~CProcessScanner(void);

	void ScanProcesses(bool bDeepScan);
	bool CheckProcess(PMAX_SCANNER_INFO pScannerInfo, bool &bStopEnum);
	bool ScanThread(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum);

private:
	WCHAR m_strProcessName[MAX_PATH];
};
