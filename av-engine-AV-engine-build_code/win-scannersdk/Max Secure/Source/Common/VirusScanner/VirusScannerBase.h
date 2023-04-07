/*======================================================================================
   FILE				: VirusScannerBase.h
   ABSTRACT			: This abstract base class, as of today supports scanning for Virus 
						using Virus Scanner
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created in 2008 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 20-Apr-2010
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/	
#pragma once
#include "MaxConstant.h"

class CVirusScannerBase
{
public:
	CVirusScannerBase();
	~CVirusScannerBase(void);

	virtual bool InitializeVirusScanner(const CString &csDBPath, BYTE *pPolyVirusRevIDS) = 0;
	virtual bool DeInitializeVirusScanner() = 0;
	virtual DWORD ScanFile(PMAX_SCANNER_INFO pScanInfo) = 0;
	virtual DWORD RepairFile(PMAX_SCANNER_INFO pScanInfo) = 0;

	void StopScanning()
	{
		m_bStopScanning = true;
	}

	bool	m_bUSBScan;
	bool	m_bIsActMon;
private:
	bool m_bStopScanning;
};