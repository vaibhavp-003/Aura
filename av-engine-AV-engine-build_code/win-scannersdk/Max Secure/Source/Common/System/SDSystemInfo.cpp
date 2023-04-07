/*=============================================================================
FILE                : CSystemInfo.h
ABSTRACT            :
DOCUMENTS           : Refer The System Design.doc, System Requirement Document.doc
AUTHOR              : Sandip Sanap
COMPANY             : Aura 
COPYRIGHT NOTICE    :
                      (C)Aura:
                      Created as an unpublished copyright work.All rights reserved.
                      This document and the information it contains is confidential and
                      proprietary to Aura.Hence, it may not be
                      used, copied, reproduced, transmitted, or stored in any form or by any
                      means, electronic, recording, photocopying, mechanical or otherwise,
                      without the prior written permission of Aura
CREATION DATE      : 25/12/2003
NOTES              : Interface for the CSystemInfo class
VERSION HISTORY    : 5 April 2008, Nupur : Added check for 64-bit Operating System.
=============================================================================*/
#include "pch.h"
#include <stdio.h>
#include <shlobj.h>
#include "SDSystemInfo.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "Registry.h"
#include "SDConstants.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// CSystemInfo
DWORD CSystemInfo::m_dwDPI = 0;
BOOL CSystemInfo::m_bAdminRight = TRUE;
BOOL CSystemInfo::m_bIsFirewallInstalled = FALSE;
CString CSystemInfo::m_strModulePath = _T("");
CString CSystemInfo::m_strAppPath = _T("");
CString CSystemInfo::m_strDBPath = _T("");
CString CSystemInfo::m_strOS = _T("");
CString CSystemInfo::m_strSP = _T("");
CString CSystemInfo::m_strSysDir = _T("");
CString CSystemInfo::m_strSysWow64Dir = _T("");
CString	CSystemInfo::m_strWinDir = _T("");
CString CSystemInfo::m_strPcName = _T("");
CString CSystemInfo::m_strDate = _T("");
CString CSystemInfo::m_strProgramFilesDir = _T("");
CString CSystemInfo::m_strProgramFilesDirX64 = _T("");
CString CSystemInfo::m_strTempDBPath = _T("");
CString CSystemInfo::m_strTempLiveupdate = _T("");
CString CSystemInfo::m_strWaitingForMerge = _T("");
CStringArray CSystemInfo::m_EnvVarArr;
CString CSystemInfo::m_strRoot = _T("");
CString CSystemInfo::m_strLogFolderPath = _T("");
CString CSystemInfo::m_strSettingPath = _T("");
CString CSystemInfo::m_csProductName = _T("");
CString CSystemInfo::m_csProductRegKey = _T("");
CString CSystemInfo::m_csSchedulerRegKey = _T("");
CString CSystemInfo::m_csSchedulerBackupRegKey = _T("");
CString CSystemInfo::m_csActMonRegKey= _T("");
CString CSystemInfo::m_csFolderInAppPath= _T("");
CString CSystemInfo::m_csFolderInAppPathParent = _T("");
CString CSystemInfo::m_csEvalDllName= _T("");
CString CSystemInfo::m_csVoucherKey= _T("");
CString CSystemInfo::m_csVoucherSubKey = _T("");
CString CSystemInfo::m_csAppPathProdName = _T("");
CString CSystemInfo::m_csEvaluationPeriod = _T("");
CString CSystemInfo::m_csProductNumber = _T("");
CString CSystemInfo::m_csX86AppPathIn64OS = _T("");
CString CSystemInfo::m_csInstallProdName = _T("");
UINT CSystemInfo::m_iVirusScanFlag = 0;
int CSystemInfo::m_iRectangleColor = 0;


BOOL    CSystemInfo::m_bIsOSX64 = false;
BOOL    CSystemInfo::m_bIs2kSevers = false;


//create global object to intialise the string variables
CSystemInfo g_objSystemInfo;
/*-------------------------------------------------------------------------------------
	Function		: CSystemInfo
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Constructor
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CSystemInfo::CSystemInfo()
{
	GetSystemInformation();
}
/*-------------------------------------------------------------------------------------
	Function		: ~CSystemInfo
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CSystemInfo::~CSystemInfo()
{
}
/*-------------------------------------------------------------------------------------
	Function		: GetSystemInformation
	In Parameters	: -
	Out Parameters	: void
	Purpose			: Get systemiformation Application path,System path,Windows path,
					: OS,DPI
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CSystemInfo::GetSystemInformation()
{
	CCPUInfo objCpuInfo;
	CProductInfo objProductInfo;
	if(CSystemInfo::m_strAppPath.GetLength( )== 0)
	{
		CSystemInfo::m_strAppPath = objProductInfo.GetAppInstallPath();
	}

	if(CSystemInfo::m_strModulePath.GetLength() == 0)
	{
		CSystemInfo::m_strModulePath = objProductInfo.GetInstallPath();
	}

	if(CSystemInfo::m_strDBPath.GetLength() == 0)
	{
		CSystemInfo::m_strDBPath = objProductInfo.GetDatabasePath();
	}

	if(CSystemInfo::m_strTempDBPath.GetLength() == 0)
	{
		CSystemInfo::m_strTempDBPath = objProductInfo.GetTempDatabasePath();
	}

	if(CSystemInfo::m_strTempLiveupdate.GetLength() == 0)
	{
		CSystemInfo::m_strTempLiveupdate = m_strAppPath + TEMP_LIVEUPDATE;
	}

	if(CSystemInfo::m_strWaitingForMerge.GetLength() == 0)
	{
		CSystemInfo::m_strWaitingForMerge = m_strAppPath + LIVEUPDATE_WAIT_FOR_MERGE;
	}

	CSystemInfo::m_bAdminRight = objCpuInfo.CheckForAdminRights();

	if(CSystemInfo::m_strOS.GetLength() == 0)
	{
		CSystemInfo::m_strOS = objCpuInfo.GetOSVerTag();
	}

	if(CSystemInfo::m_strSP.GetLength() == 0)
	{
		CString csSP;
		CRegistry objReg;
		objReg.Get(OS_VERSION_REG,_T("CSDVersion"),csSP,HKEY_LOCAL_MACHINE);
		CSystemInfo::m_strSP = csSP;
	}

	if(CSystemInfo::m_strSysDir.GetLength() == 0)
	{
		CSystemInfo::m_strSysDir = objCpuInfo.GetSystemDir();
	}

	if(CSystemInfo::m_strSysWow64Dir.GetLength() == 0)
	{
		CSystemInfo::m_strSysWow64Dir = objCpuInfo.GetSystemWow64Dir();
	}

	if(CSystemInfo::m_strSysWow64Dir.GetLength() == 0)
	{
		if(CSystemInfo::m_strWinDir.GetLength() == 0)
		{
			CSystemInfo::m_strWinDir = objCpuInfo.GetWindowsDir();
		}
	}

	if(CSystemInfo::m_strProgramFilesDir.GetLength() == 0)
	{
		CSystemInfo::m_strProgramFilesDir = objCpuInfo.GetProgramFilesDir();
	}

	if(CSystemInfo::m_strProgramFilesDirX64.GetLength() == 0)
	{
		CSystemInfo::m_strProgramFilesDirX64 = objCpuInfo.GetProgramFilesDirX64();
	}

	if(CSystemInfo::m_dwDPI == 0)
	{
		CSystemInfo::m_dwDPI = objCpuInfo.GetDpiValue();
	}

	if(CSystemInfo::m_EnvVarArr.GetCount() == 0)
	{
		objCpuInfo.GetAllEnvVariable(m_EnvVarArr);
	}

	if(CSystemInfo::m_strPcName.GetLength() == 0)
	{
		CSystemInfo::m_strPcName = objCpuInfo.GetPCName();
	}

	if(CSystemInfo::m_strDate.GetLength() == 0)
	{
		CSystemInfo::m_strDate = objCpuInfo.GetDate();
	}

	if(CSystemInfo::m_strRoot.GetLength() == 0)
	{
		CSystemInfo::m_strRoot = objCpuInfo.GetRootDrive();
	}

	if(CSystemInfo::m_strLogFolderPath.GetLength() == 0)
	{
		CSystemInfo::m_strLogFolderPath = objProductInfo.GetLogPath();
	}

	if(CSystemInfo::m_strSettingPath.GetLength() == 0)
	{
		CSystemInfo::m_strSettingPath = objProductInfo.GetSettingPath();
	}
	if(CSystemInfo::m_csProductName.GetLength() == 0)
	{
		CSystemInfo::m_csProductName = objProductInfo.GetProductName();
	}
	if(CSystemInfo::m_csProductRegKey.GetLength() == 0)
	{
		CSystemInfo::m_csProductRegKey = objProductInfo.GetProductRegKey();
	}
	if(CSystemInfo::m_csSchedulerRegKey.GetLength() == 0)
	{
		CSystemInfo::m_csSchedulerRegKey = objProductInfo.GetSchedulerRegKey();
	}
	if(CSystemInfo::m_csSchedulerBackupRegKey.GetLength() == 0)
	{
		CSystemInfo::m_csSchedulerBackupRegKey = objProductInfo.GetSchedulerBackupRegKey();
	}
	if(CSystemInfo::m_csActMonRegKey.GetLength() == 0)
	{
		CSystemInfo::m_csActMonRegKey = objProductInfo.GetActMonRegKey();
	}
	if(CSystemInfo::m_csFolderInAppPath.GetLength() == 0)
	{
		CSystemInfo::m_csFolderInAppPath = objProductInfo.GetFolderInAppPath();
	}
	if (CSystemInfo::m_csFolderInAppPathParent.GetLength() == 0)
	{
		CSystemInfo::m_csFolderInAppPathParent = objProductInfo.GetFolderInAppPathParent();
	}
	if(CSystemInfo::m_csEvalDllName.GetLength() == 0)
	{
		CSystemInfo::m_csEvalDllName = objProductInfo.GetEvaluationDllName();
	}
	if(CSystemInfo::m_csVoucherKey.GetLength() == 0)
	{
		CSystemInfo::m_csVoucherKey = objProductInfo.GetVoucherKey();
	}
	if(CSystemInfo::m_csVoucherSubKey.GetLength() == 0)
	{
		CSystemInfo::m_csVoucherSubKey = objProductInfo.GetVoucherSubKey();
	}
	if(CSystemInfo::m_csEvaluationPeriod.GetLength() == 0)
	{
		CSystemInfo::m_csEvaluationPeriod = objProductInfo.GetEvaluationPeriod();
	}
	if(CSystemInfo::m_csProductNumber.GetLength() == 0)
	{
		CSystemInfo::m_csProductNumber = objProductInfo.GetProductNumber();
	}
	if(CSystemInfo::m_csAppPathProdName.GetLength() == 0)
	{
		CSystemInfo::m_csAppPathProdName = objProductInfo.GetAppPathProdFolder();
	}
	if (CSystemInfo::m_csInstallProdName.GetLength() == 0)
	{
		CSystemInfo::m_csInstallProdName = objProductInfo.GetInstallProdName();
	}
	CSystemInfo::m_iVirusScanFlag = objProductInfo.GetVirusScanFlag();
	CSystemInfo::m_bIsOSX64 = objCpuInfo.isOS64bit();
	CSystemInfo::m_bIs2kSevers = CheckFor2kSevers();
	CSystemInfo::m_bIsFirewallInstalled = IsFirewallInstalled();
	CSystemInfo::m_csX86AppPathIn64OS = CSystemInfo::m_strProgramFilesDirX64 + L"\\" + CSystemInfo::m_csInstallProdName;
	CSystemInfo::m_iRectangleColor = objProductInfo.GetRectColor();
}
/*-------------------------------------------------------------------------------------
	Function		: GetDirectoryPath
	In Parameters	: CSIDL_ID - CSIDL ID
	Out Parameters	: CString : Folder path
	Purpose			: Get Directory path by CSIDL ID
					:
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/

CString CSystemInfo::GetDirectoryPath(DWORD CSIDL_ID)
{
	CCPUInfo objCpuInfo;
	return objCpuInfo.GetDirectoryPath(CSIDL_ID);
}

BOOL CSystemInfo::CheckFor2kSevers()
{
	if(CSystemInfo::m_strOS == CString(W2K)+CString(SER) || CSystemInfo::m_strOS == CString(W2K)+CString(DCS) ||
	   CSystemInfo::m_strOS == CString(W2K)+CString(ADS) || CSystemInfo::m_strOS == CString(W2K)+CString(ENS))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CSystemInfo::IsFirewallInstalled()
{
	CProductInfo oProductInfo;	
	
	CString csFirewallPath = oProductInfo.GetFirewallFolderPath();
	if(csFirewallPath.GetLength() == 0)
	{
		return FALSE;
	}
	return TRUE;
}