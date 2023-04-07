/*======================================================================================
FILE             : RegistryScanner.cpp
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
				  
CREATION DATE    : 8/1/2009 7:47:01 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "RegistryScanner.h"
#include "MaxExceptionFilter.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CRegistryScanner::CRegistryScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CRegistryScanner::CRegistryScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryScanner::~CRegistryScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CRegistryScanner::~CRegistryScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryScanner::ScanRegistry
In Parameters  : const CS2U& objFilesList, const CS2U& objFoldersList, bool bScanReferences
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryScanner::ScanRegistry(CS2U* pobjFilesList, CS2U* pobjFoldersList, bool bScanReferences)
{
	m_bScanReferences = bScanReferences;
	m_pobjFilesList = pobjFilesList;
	m_pobjFoldersList = pobjFoldersList;

	/*__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_AppInit_DLL_Scanner, L"AppInit_Dll Scan");
			SendScanStatusToUI(Starting_AppInit_DLL_Scanner);
			StartAppInitScan();
			AddLogEntry(Starting_AppInit_DLL_Scanner, L"AppInit_Dll Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner AppInit_Dll Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_BHO_Scanner, L"BHO Scan");
			SendScanStatusToUI(Starting_BHO_Scanner);
			StartBHOScan();
			AddLogEntry(Starting_BHO_Scanner, L"BHO Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner BHO Scan Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_ActiveX_Scanner, L"Starting ActiveX Scan");
			SendScanStatusToUI(Starting_ActiveX_Scanner);
			StartActiveXScan();
			AddLogEntry(Starting_ActiveX_Scanner, L"Starting ActiveX Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner ActiveX Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_MenuExt_Key_Scanner, L"MenuExt Key Scan");
			SendScanStatusToUI(Starting_MenuExt_Key_Scanner);
			StartMenuExtScan();
			AddLogEntry(Starting_MenuExt_Value_Scanner, L"MenuExt Value Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner MenuExt Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_RunEntry_Scanner, L"Run Entry Scan");
			SendScanStatusToUI(Starting_RunEntry_Scanner);
			StartRunScan();
			AddLogEntry(Starting_RunEntry_Scanner, L"Run Entry Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner RunEntry Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_Toolbar_Scanner, L"Toolbar Scan");
			SendScanStatusToUI(Starting_Toolbar_Scanner);
			StartTooBarScan();
			AddLogEntry(Starting_Toolbar_Scanner, L"Toolbar Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner ToolBar Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_Services_Scanner, L"Services Scan");
			SendScanStatusToUI(Starting_Services_Scanner);
			StartServicesScan();
			AddLogEntry(Starting_Services_Scanner, L"Services Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner Services Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_SSODL_Scanner, L"SSODL Scan");
			SendScanStatusToUI(Starting_SSODL_Scanner);
			StartSSODLScan();
			AddLogEntry(Starting_SSODL_Scanner, L"SSODL Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner SSODL Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_SharedTask_Scanner, L"SharedTask Scan");
			SendScanStatusToUI(Starting_SharedTask_Scanner);
			StartSharedTaskScan();
			AddLogEntry(Starting_SharedTask_Scanner, L"SharedTask Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner SharedTask Mode")))
	{
	}
	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_SharedDlls_Scanner, L"SharedDlls Scan");
			SendScanStatusToUI(Starting_SharedDlls_Scanner);
			StartSharedDllScan();
			AddLogEntry(Starting_SharedDlls_Scanner, L"SharedDlls Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner SharedDlls Mode")))
	{
	}
	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_ShellExecuteHooks_Scanner, L"ShellExecuteHooks Scan");
			SendScanStatusToUI(Starting_ShellExecuteHooks_Scanner);
			StartShellExecuteHooksScan();
			AddLogEntry(Starting_ShellExecuteHooks_Scanner, L"ShellExecuteHooks Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner ShellExecuteHooks Mode")))
	{
	}
	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_Notify_Scanner, L"Notify Scan");
			SendScanStatusToUI(Starting_Notify_Scanner);
			StartNotifyScan();
			AddLogEntry(Starting_Notify_Scanner, L"Notify Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner Notify Mode")))
	{
	}*/

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_RegVal_Scanner, L"RegVal Scan");
			SendScanStatusToUI(Starting_RegVal_Scanner);
			StartRegValScan();
			AddLogEntry(Starting_RegVal_Scanner, L"RegVal Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner RegVal Mode")))
	{
	}

	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_RegKey_Scanner, L"RegKey Scan");
			SendScanStatusToUI(Starting_RegKey_Scanner);
			StartRegKeyScan();
			AddLogEntry(Starting_RegKey_Scanner, L"RegKey Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner RegKey Mode")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryScanner::ScanRegFixEntry
In Parameters  : bool bRegFixForOptionTab, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryScanner::ScanRegFixEntry(bool bRegFixForOptionTab)
{
	__try
	{
		if(!m_bStopScanning)
		{
			AddLogEntry(Starting_RegFix_Scanner, L"RegFix Scan");
			SendScanStatusToUI(Starting_RegFix_Scanner);
			StartRegFixScan(bRegFixForOptionTab);
			AddLogEntry(Starting_RegFix_Scanner, L"RegFix Scan", 0, 0, 0, 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner ScanRegFixEntry Mode")))
	{
	}
}