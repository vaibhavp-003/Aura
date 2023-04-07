/*=============================================================================
   FILE			: ProductInfo.h
   ABSTRACT		: This class provides methods to get Product specific Information.
   DOCUMENTS	: 
   AUTHOR		: Nupur Aggarwal 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 16/08/2007
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/
#pragma once
#include "pch.h"
#include "Registry.h"
#include "Constants.h"

typedef struct tagVersionInformation
{
	TCHAR szKey[100];
	TCHAR szValue[100];
}VER_DATA;

class CProductInfo
{
public:

	CProductInfo(void);
	~CProductInfo(void);
	
	CString GetAppInstallPath();
	CString GetAppInstallPathx86();
	CString GetProductVersion();
	CString GetVoucherNo();
	CString	GetInstallPath();
	CString GetDatabasePath();
	CString GetTempDatabasePath();
	CString GetLogPath();
	CString GetSettingPath();
	CString GetCurrentSettingIniPath();
	CString GetProductRegKey();
	CString GetSchedulerRegKey() {return GetStringDataFromIni(_T("SCHEDULEKEY"));};
	CString GetSchedulerBackupRegKey() {return GetStringDataFromIni(_T("BACKUPSCHEDULEKEY"));};
	CString GetActMonRegKey() {return GetStringDataFromIni(_T("PROTECTIONKEY"));};
	CString GetProductName() {return GetStringDataFromIni(_T("PRODUCTNAME"));};
	CString GetFolderInAppPath(){return GetStringDataFromIni(_T("SD_PRODUCT_APP_PATH"));};
	CString GetFolderInAppPathParent() { return GetStringDataFromIni(_T("APP_PATH_PROD_PARENT")); };
	CString GetEvaluationDllName(){return GetStringDataFromIni(_T("EVALUATION_DLL"));};
	CString GetVoucherKey(){return GetStringDataFromIni(_T("VOUCHER_KEY"));};
	CString GetVoucherSubKey(){return GetStringDataFromIni(_T("REGISTARIONREGKEY"));};//PRODUCTREGKEY
	CString GetEvaluationPeriod(){ return EVALUATION_PERIOD; /*GetStringDataFromIni(_T("EVALUATION_PERIOD"));*/};
	CString GetProductNumber(){ return GetStringDataFromIni(_T("PRODUCTNUM"));};//VERSION
	CString GetAppPathProdFolder(){ return GetStringDataFromIni(_T("APP_PATH_PROD_FOLDER"));};
	CString GetInstallProdName() { return GetStringDataFromIni(_T("PRODUCTPATH")); };
	UINT GetVirusScanFlag(){ return GetPrivateProfileInt(SETTING_VAL_INI, _T("AV_SCAN"), 0, m_csCurrentSettingIniPath);};

	BOOL EnableDisableFireWall(DWORD dwEnable);
	DWORD GetFwStatus();
	ENUM_PRODUCT_TYPE GetProductType();
	CString GetFirewallFolderPath();
	CString GetFirewallExePath();
	CString GetProductAppFolderPath(ENUM_PRODUCT_TYPE eProductType = INVALID_ID);
	void DumpVersionInfo();
	bool SquareCorners();
	int GetRectColor();


private:
	CRegistry m_objRegistry;
	CString GetModulePath();
	CString GetStringDataFromIni(TCHAR *csVal);
	UINT GetColorDataFromIni(TCHAR *csVal);
	CString GetInstProductAlongWithFW(ENUM_PRODUCT_TYPE &eProductType);	

	CString m_csCurrentSettingIniPath;
	CString m_csProductRegKey;
	UINT m_iColorCode;
};
