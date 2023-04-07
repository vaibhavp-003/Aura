/*======================================================================================
   FILE				: VipreVirusScanner.h
   ABSTRACT			: This class supports for scanning for Virus using Vipre Virus Scanner
						SDK 3.0
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
#include "VirusScannerBase.h"
#include "Primal.h"
#include "VipreSdkTypes.h"
#include "VipreSdk.h"

class CVipreVirusScanner
{
public:
	CVipreVirusScanner();
	~CVipreVirusScanner(void);

	bool m_bStopScanning;

	bool InitializeVirusScanner(const CString &csDBPath);
	bool DeInitializeVirusScanner();
	bool ScanFile(PMAX_SCANNER_INFO pScanInfo);
	bool RepairFile(PMAX_SCANNER_INFO pScanInfo);
	void StopScanning()
	{
		m_bStopScanning = true;
	}

private:
	HMODULE m_hVipreDLL;
	VIPRE_DISPATCHER m_VipreDispatcher;			// VIPRE Controller dispatch method
	bool GetDefinitionsPath(LPTSTR pwcsDefPath, DWORD dwBufLen);
};