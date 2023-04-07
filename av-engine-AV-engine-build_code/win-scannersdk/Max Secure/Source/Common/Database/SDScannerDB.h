/*======================================================================================
FILE             : SDScannerDB.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 14 March, 2009.
NOTES		     : Stores the Scan Statistics in a DB
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "S2U.h"

class CSDScannerDB
{
public:
	CSDScannerDB(void);
	~CSDScannerDB(void);

	bool FindWormInScanDB(const CString &csPath);
	bool RemoveWormFromScanDB(const CString &csPath);
	void AddEntryinGraphINI(const int &threatIndex);
	void AddEntryinScanDB(const CString &csWorm, DWORD dwSpyID = 0);
	bool ReadScanDBFile();
	bool SaveScanDBFile();
	bool IsScanDBLoaded();
	void UnLoadScanDB();
	CString GetStringFromINI(const CString& csINIHeader, const CString& csINISection);
	bool WriteCountInINI();
private:
	int m_iHighCount;
	int m_iMediumCount;
	int m_iCriticalCount;
	int m_iLowCount;
	CS2U m_objScanDB;
	CString m_csINIFilePath;
};
