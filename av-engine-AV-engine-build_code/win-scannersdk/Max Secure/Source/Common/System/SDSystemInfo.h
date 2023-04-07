/*=============================================================================
FILE                : CSystemInfo.h
ABSTRACT            :
DOCUMENTS           : Refer The System Design.doc, System Requirement Document.doc
AUTHOR              : Sandip Sanap
COMPANY             : Aura 
COPYRIGHT NOTICE    :
                      (C)Aura:
                      Created as an unpublished copyright work. All rights reserved.
                      This document and the information it contains is confidential and
                      proprietary to Aura. Hence, it may not be
                      used, copied, reproduced, transmitted, or stored in any form or by any
                      means, electronic, recording, photocopying, mechanical or otherwise,
                      without the prior written permission of Aura
CREATION DATE      : 25/12/2003
NOTES              : Interface for the CSystemInfo class
VERSION HISTORY    : 5 April 2008, Nupur : Added check for 64-bit Operating System.
=============================================================================*/
#ifndef _SYSINFO
#define _SYSINFO
#pragma once

class CSystemInfo
{
public:
	CSystemInfo();
	virtual ~CSystemInfo();

	static CString m_strOS;
	static CString m_strSP;
	static CString m_strSysDir;
	static CString m_strSysWow64Dir;
	static CString m_strWinDir;
	static CString m_strAppPath;
	static CString m_strModulePath;
	static CString m_strDBPath;
	static CString m_strTempDBPath;
	static CString m_strTempLiveupdate;
	static CString m_strWaitingForMerge;
	static CString m_strProgramFilesDir;
	static CString m_strProgramFilesDirX64;
	static CString m_strPcName;
	static CString m_strDate;
	static CString m_strRoot;
	static CString m_strLogFolderPath;
	static CString m_strSettingPath;
	static CString m_csProductName;
	static CString m_csProductRegKey;
	static CString m_csSchedulerRegKey;
	static CString m_csSchedulerBackupRegKey;
	static CString m_csActMonRegKey;
	static CString m_csFolderInAppPath;
	static CString m_csFolderInAppPathParent;
	static CString m_csEvalDllName;
	static CString m_csVoucherKey;
	static CString m_csVoucherSubKey;
	static CString m_csEvaluationPeriod;
	static CString m_csProductNumber;
	static CString m_csAppPathProdName;
	static CString m_csInstallProdName;
	static CString m_csX86AppPathIn64OS; // only used in 32 bit application
	static UINT m_iVirusScanFlag;
	static DWORD m_dwDPI;
	static BOOL m_bAdminRight;
	static CStringArray m_EnvVarArr;
	static CString GetDirectoryPath(DWORD CSIDL_ID);
	static BOOL CheckFor2kSevers();
	static BOOL m_bIsOSX64;
	static BOOL m_bIs2kSevers;
	static void GetSystemInformation();
	static CString GetOS();
	static BOOL m_bIsFirewallInstalled;
	static BOOL IsFirewallInstalled();
	static int m_iRectangleColor;
};

#endif