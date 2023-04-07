/*=============================================================================
   FILE			: ProductInfo.cpp
   ABSTRACT		: This class provides methods to get Product specific Information.
   DOCUMENTS	: 
   AUTHOR		: Nupur Aggarwal
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C)Aura
				Created as an unpublished copyright work. All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura. Hence, it may not be
				used, copied, reproduced, transmitted, or stored in any form or by any
				means, electronic, recording, photocopying, mechanical or otherwise,
				with out the prior written permission of Aura
CREATION DATE   : 16/08/2007
   NOTES		:
VERSION HISTORY	:
============================================================================*/
#include "pch.h"
#include "ProductInfo.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CProductInfo(Constructor)
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This Function  Initilaize CCPUInfo class
	Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CProductInfo::CProductInfo()
{
	GetCurrentSettingIniPath();
	GetProductRegKey();
}

/*-------------------------------------------------------------------------------------
	Function		: ~CProductInfo (Destructor)
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This Function Destruct CCPUInfo class.
	Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CProductInfo::~CProductInfo()
{

}

/*-------------------------------------------------------------------------------------
	Function		: GetAppInstallPath
	In Parameters	: -
	Out Parameters	: CString : string containg Installtion path  
	Purpose			: This Function obtain Installtion path on
					  local machine
	Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetAppInstallPath()
{
	try
	{
		CString strAppInstallPath;
		m_objRegistry.Get(m_csProductRegKey, APP_FOLDER_KEY, strAppInstallPath, HKEY_LOCAL_MACHINE);
		return strAppInstallPath.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CProductInfo::GetRCInstallPath"));
	}
	return CString(_T(""));
}

CString CProductInfo::GetAppInstallPathx86()
{
	try
	{
		CString strAppInstallPath;
		m_objRegistry.Get(MAXMGR_DRIVE_REG_KEY, _T("SDAppPathx86"), strAppInstallPath, HKEY_LOCAL_MACHINE);
		strAppInstallPath.Replace(_T("\\??\\"), _T(""));		/* remove \??\*/
		return strAppInstallPath.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CProductInfo::GetRCInstallPath"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
	Function		: GetProductVersion
	In Parameters	: -
 	Out Parameters	: CString : string containg version number
	Purpose			: This Function obtain version number on local machine
	Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetProductVersion()
{
	try
	{
		CString csProductVer;
		m_objRegistry.Get(m_csProductRegKey, _T("ProductVersionNo"), csProductVer, HKEY_LOCAL_MACHINE);
		return csProductVer.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CProductInfo::GetProductVersion"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
	Function		: GetVoucherNo
	In Parameters	: -
	Out Parameters	: CString : string containg Voucher Name
	Purpose			: This Function obtain Voucher Name on local machine
	Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetVoucherNo()
{
	try
	{
		CString csVoucherNo = _T("");
		if(m_objRegistry.ValueExists(GetVoucherKey(), VOUCHER_NUMBER, HKEY_LOCAL_MACHINE))
		{
			m_objRegistry.Get(GetVoucherKey(), VOUCHER_NUMBER, csVoucherNo, HKEY_LOCAL_MACHINE);
			return csVoucherNo.Trim();
		}
		else
		{
			return csVoucherNo;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CProductInfo::GetRCVoucherNo"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
	Function		: GetInstallPath
	In Parameters	: -
	Out Parameters	: CString : string containg Installtion Path
	Purpose			: This Function obtain Installtion Path on local machine
	Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetInstallPath()
{
	try
	{
        TCHAR sExeFileName[MAX_FILE_PATH]={0};
		GetModuleFileName((HINSTANCE)&__ImageBase, sExeFileName, MAX_FILE_PATH);
		CString csCheckPath(sExeFileName);
		csCheckPath.MakeLower();

		if((csCheckPath.Find(L"msiexec.exe") == -1))		// Special handling required for MSI Setup
		{
 			CString csInstallPath;
			csInstallPath = sExeFileName;
			if((csInstallPath.Find(L"\\Tools\\") != -1))
			{
				CString csModulePath = csInstallPath.Left(csInstallPath.ReverseFind(_T('\\')));
				csModulePath = csModulePath.Left(csModulePath.ReverseFind(_T('\\')));
				return (csModulePath + BACK_SLASH);				
			}
			
			int iPos = 0;
			iPos = csInstallPath.ReverseFind('\\');
			if(iPos == -1)
			{
				return (csInstallPath + BACK_SLASH);
			}
			else
			{
				csInstallPath = csInstallPath.Mid(0, iPos);
				return (csInstallPath + BACK_SLASH);
			}
		}

		CString csAppFolder;
		ENUM_PRODUCT_TYPE eProductType;
		csAppFolder = GetInstProductAlongWithFW(eProductType);

		OutputDebugString(L"##################################################################################");
		OutputDebugString(L"##################################################################################");
		OutputDebugString(L"##### " + csAppFolder + sExeFileName);
		OutputDebugString(L"##################################################################################");
		OutputDebugString(L"##################################################################################");

		return csAppFolder;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CProductInfo::GetInstallPath"));
	}
	return CString(_T(""));
}
//This is right now for SD only
/*-------------------------------------------------------------------------------------
	Function		: GetDatabasePath
	In Parameters	: -
	Out Parameters	: CString : Database path
	Purpose			: Get Database path
					:

--------------------------------------------------------------------------------------*/

CString CProductInfo::GetDatabasePath()
{
	CString strDBPath;
	CRegistry objReg;
	objReg.Get(m_csProductRegKey, APP_FOLDER_KEY, strDBPath, HKEY_LOCAL_MACHINE);
	strDBPath += DATABASEFOLDER;
	return strDBPath;
}
/*-------------------------------------------------------------------------------------
	Function		: GetTempDatabasePath
	In Parameters	: -
	Out Parameters	: CString : Database path
	Purpose			: Get Temporary Database path
					:

--------------------------------------------------------------------------------------*/

CString CProductInfo::GetTempDatabasePath()
{
	CString strDBPath;
	CRegistry objReg;
	objReg.Get(m_csProductRegKey, APP_FOLDER_KEY, strDBPath, HKEY_LOCAL_MACHINE);
	strDBPath += TEMP_LIVEUPDATE_DATA;
	return strDBPath;
}
/*-------------------------------------------------------------------------------------
	Function		: GetLogPath
	In Parameters	: -
	Out Parameters	: CString : Log folder path
	Purpose			: Get Log folder path
					:
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/

CString CProductInfo::GetLogPath()
{
	CString strLogPath;
	CRegistry objReg;
	objReg.Get(m_csProductRegKey, APP_FOLDER_KEY, strLogPath, HKEY_LOCAL_MACHINE);
	strLogPath += LOGFOLDER;
	return strLogPath;
}
/*-------------------------------------------------------------------------------------
	Function		: GetSettingPath
	In Parameters	: -
	Out Parameters	: CString : Setting folder path
	Purpose			: Get setting path
					:
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetSettingPath()
{
	CString strSettingPath;
	CRegistry objReg;
	objReg.Get(m_csProductRegKey, APP_FOLDER_KEY, strSettingPath, HKEY_LOCAL_MACHINE);
	strSettingPath += SETTINGFOLDER;
	strSettingPath += _T("\\");
	return strSettingPath;
}

/*-------------------------------------------------------------------------------------
	Function		: GetCurrentSettingIniPath
	In Parameters	: -
	Out Parameters	: CString : CurrentSettings.ini path
	Purpose			: Get CurrentSettings.ini path
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetCurrentSettingIniPath()
{
	m_csCurrentSettingIniPath = GetInstallPath() + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	return m_csCurrentSettingIniPath;
}

/*-------------------------------------------------------------------------------------
	Function		: GetStringDataFromIni
	In Parameters	: -
	Out Parameters	: CString : Data from ini
	Purpose			: Get data for corresponding value from CurrentSettings.ini
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetStringDataFromIni(TCHAR *csVal)
{
	TCHAR szData[MAX_PATH] = {0};
	GetPrivateProfileString(SETTING_VAL_INI, csVal, _T(""), szData, MAX_PATH, m_csCurrentSettingIniPath);
	return CString(szData);
}

/*-------------------------------------------------------------------------------------
	Function		: GetProductRegKey
	In Parameters	: -
	Out Parameters	: CString : Registry key
	Purpose			: Get product's main reg key from current setting ini file
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetProductRegKey()
{
	m_csProductRegKey = GetStringDataFromIni(_T("PRODUCT_REG"));
	return m_csProductRegKey;
}

/*-------------------------------------------------------------------------------------
	Function		: EnableDisableFireWall
	In Parameters	: DWORD dwEnable
	Out Parameters	: BOOL
	Purpose			: Enable Disable Firewall as Per Our Installed Product
					:	0 - Disable
					:	1 - Enable
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CProductInfo::EnableDisableFireWall(DWORD dwEnable)
{
	CRegistry objReg;
	objReg.Set(FW_DRIVER_PATH, _T("FireWallEnable"), dwEnable, HKEY_LOCAL_MACHINE);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFwStatus
	In Parameters	: -
	Out Parameters	: DWORD
	Purpose			: Get Firewall Status as per Our Installed product
					:	0 - Disable
					:	1 - Enable
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
DWORD CProductInfo::GetFwStatus()
{
	CRegistry objReg;
	DWORD dwReturnStatus = (DWORD)-1;
	objReg.Get(FW_DRIVER_PATH, _T("FireWallEnable"), dwReturnStatus, HKEY_LOCAL_MACHINE);
	return dwReturnStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetProductType
	In Parameters	: -
	Out Parameters	: ENUM_PRODUCT_TYPE
	Purpose			: This Return's Installed Product ID
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
ENUM_PRODUCT_TYPE CProductInfo::GetProductType()
{
	bool bFound = false;
	CString csAppPath, csModulePath = GetModulePath();
	ENUM_PRODUCT_TYPE eProductType = INVALID_ID;
	
	if(_tcsstr(csModulePath, L"\\UltraAV\\") != NULL)
	{
		if(_waccess(csModulePath, 0) == 0)
			eProductType = ENUM_ULTRAAV;
	}
	else if(_tcsstr(csModulePath, L"\\AuFirewall\\") != NULL)
	{
		bFound = false;
		if(!bFound)
		{
			csAppPath = BLANKSTRING;
			if(m_objRegistry.Get(ULTRAAV_REG_KEY, APP_FOLDER_KEY, csAppPath, HKEY_LOCAL_MACHINE))
			{
				if(!_taccess_s(csAppPath, 0))
				{
					bFound = true;
					eProductType = ENUM_ULTRAAV;
				}
			}
		}

		if(!bFound && !_waccess(csModulePath, 0))
		{
			eProductType = ENUM_FIREWALL;
		}
	}

	return eProductType;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFirewallFolderPath
	In Parameters	: -
	Out Parameters	: CString
	Purpose			: This Return's Firewall Installed Path
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetFirewallFolderPath()
{
	CString csReturn(_T(""));
	CRegistry objReg;
	if(objReg.Get(FIREWALL_REG_KEY, L"AppFolder", csReturn, HKEY_LOCAL_MACHINE))
	{
		return csReturn;
	}
	return csReturn;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFirewallExePath
	In Parameters	: -
	Out Parameters	: CString
	Purpose			: This Return's Firewall Exe Path
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetFirewallExePath()
{
	CString csReturn(_T(""));
	CRegistry objReg;
	if(objReg.Get(FIREWALL_REG_KEY, L"AppPath", csReturn, HKEY_LOCAL_MACHINE))
	{
		return csReturn;
	}
	return csReturn;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFirewallFolderPath
	In Parameters	: - ENUM_PRODUCT_TYPE
	Out Parameters	: CString
	Purpose			: This Return's product installed Path on basis of Product type
	Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetProductAppFolderPath(ENUM_PRODUCT_TYPE eProductType)
{
	CString csReturn(_T(""));
	CRegistry objReg;

	if(INVALID_ID == eProductType)
	{
		eProductType = GetProductType();
	}
	
	switch(eProductType)
	{
	case ENUM_ULTRAAV:
		{
			objReg.Get(ULTRAAV_REG_KEY, APP_FOLDER_KEY, csReturn, HKEY_LOCAL_MACHINE);
		}
		break;
	case ENUM_FIREWALL:
		{
			objReg.Get(FIREWALL_REG_KEY, APP_FOLDER_KEY, csReturn, HKEY_LOCAL_MACHINE);
		}
		break;
	case INVALID_ID:
		csReturn = _T("-"); //on purpose '-' so that error comes, and not blank as it may mean a valid path when using by + cstring
	}
	return csReturn;
}

/*-------------------------------------------------------------------------------------
	Function		: GetModulePath
	In Parameters	: void
	Out Parameters	: CString
	Purpose			: private function returns Module path
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetModulePath()
{
	WCHAR wFilePath[MAX_PATH] = {0};
	GetModuleFileName((HINSTANCE)&__ImageBase, wFilePath, MAX_PATH);
	CString csCheckPath(wFilePath);

	csCheckPath.MakeLower();
	if(csCheckPath.Find(L"msiexec.exe") == -1)		// Special handling required for MSI Setup
	{
		return wFilePath;
	}

	CString csAppFolder;
	ENUM_PRODUCT_TYPE eProductType;
	csAppFolder = GetInstProductAlongWithFW(eProductType);

	OutputDebugString(L"##################################################################################");
	OutputDebugString(L"##################################################################################");
	OutputDebugString(L"##### " + csAppFolder + wFilePath);
	OutputDebugString(L"##################################################################################");
	OutputDebugString(L"##################################################################################");

	return csAppFolder;
}

/*-------------------------------------------------------------------------------------
	Function		: GetInstProductAlongWithFW
	In Parameters	: void
	Out Parameters	: CString
	Purpose			: If Firewall installed will return installed product path
					  (Checked with presence of AUGUIRES.DLL)
	Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CString CProductInfo::GetInstProductAlongWithFW(ENUM_PRODUCT_TYPE &eProductType)
{
	CProductInfo oProductInfo;
	CString csProductPath , csFilePath;
	csProductPath =  csFilePath = L"";
	
	eProductType = ENUM_FIREWALL;
	CRegistry objReg;
	objReg.Get(FIREWALL_REG_KEY, L"AppFolder", csProductPath, HKEY_LOCAL_MACHINE);
	if(csProductPath.Trim().GetLength() > 0)
	{
		csFilePath = csProductPath + L"AuGuiRes.dll";
		if(_waccess(csFilePath, 0) == 0)
		{
			return csProductPath;
		}
	}

	
	eProductType = ENUM_ULTRAAV;
	csProductPath = oProductInfo.GetProductAppFolderPath(eProductType);
	if(csProductPath.Trim().GetLength() > 0)
	{		
		csFilePath = csProductPath + L"AuGuiRes.dll";
		if(_waccess(csFilePath, 0) == 0)
		{
			return csProductPath;
		}
	}


	eProductType = INVALID_ID;
	return L"";
}

void CProductInfo::DumpVersionInfo()
{
	LPCTSTR szKeyList[] =
	{
		_T("ProductVersionNo"),
		_T("VirusVersionNo"),
		_T("DatabaseVersionNo"),
		_T("LastLiveUpdate"),
		_T("UpdateVersion"),
		_T("InfoReadTime")
	};

	struct
	{
		bool bValid;
		VER_DATA stVerData[_countof(szKeyList)];
	}stVersionHistory[1] = {0};

	SYSTEMTIME stLT = {0};
	TCHAR szSection[50] = {0};
	CString csData, csIniFilePath, csProductRegKey;

	GetLocalTime(&stLT);
	CTime objTime(stLT.wYear, stLT.wMonth, stLT.wDay, stLT.wHour, stLT.wMinute, stLT.wSecond);

	csProductRegKey = GetProductRegKey();
	csIniFilePath = GetProductAppFolderPath() + _T("Log\\VersionInformation.txt");

	for(int i = 0; i < _countof(stVersionHistory); i++)
	{
		for(int j = 0; j < _countof(stVersionHistory[i].stVerData); j++)
		{
			if(_tcslen(szKeyList[j]) < _countof(stVersionHistory[i].stVerData[j].szKey))
			{
				_tcscpy_s(stVersionHistory[i].stVerData[j].szKey, szKeyList[j]);
			}
		}
	}

	for(int i = 1; i < _countof(stVersionHistory); i++)
	{
		_stprintf_s(szSection, _countof(szSection), _T("%i"), i - 1);
		for(int j = 0; j < _countof(stVersionHistory[i].stVerData); j++)
		{
			GetPrivateProfileStringW(szSection, stVersionHistory[i].stVerData[j].szKey, BLANKSTRING,
				stVersionHistory[i].stVerData[j].szValue, _countof(stVersionHistory[i].stVerData[j].szValue),csIniFilePath);
			if(0 != stVersionHistory[i].stVerData[j].szValue[0])
			{
				stVersionHistory[i].bValid = true;
			}
		}
	}

	stVersionHistory[0].bValid = true;
	for(int i = 0; i < _countof(stVersionHistory[0].stVerData); i++)
	{
		if(i + 1 == _countof(stVersionHistory[0].stVerData))
		{
			csData = objTime.Format(_T("%a, %m/%d/%Y, %I:%M:%S %p"));
		}
		else
		{
			m_objRegistry.Get(csProductRegKey, stVersionHistory[0].stVerData[i].szKey,csData, HKEY_LOCAL_MACHINE);
		}

		if(csData != _T(""))
		{
			if(_tcslen(csData) < _countof(stVersionHistory[0].stVerData[i].szValue))
			{
				_tcscpy_s(stVersionHistory[0].stVerData[i].szValue, csData);
			}
			else
			{
				_tcscpy_s(stVersionHistory[0].stVerData[i].szValue, _T("LD"));
			}
		}
		else
		{
			_tcscpy_s(stVersionHistory[0].stVerData[i].szValue, _T("NA"));
		}
	}

	DeleteFile(csIniFilePath);
	for(int i = 0; i < _countof(stVersionHistory); i++)
	{
		if(stVersionHistory[i].bValid)
		{
			_stprintf_s(szSection, _countof(szSection), _T("%i"), i);
			for(int j = 0; j < _countof(stVersionHistory[i].stVerData); j++)
			{
				WritePrivateProfileString(szSection, stVersionHistory[i].stVerData[j].szKey, stVersionHistory[i].stVerData[j].szValue, csIniFilePath);
			}
		}
	}
}

bool CProductInfo::SquareCorners()
{
	static bool bAlreadyRead = false;
	static bool bSquareCorners = false;
	if(!bAlreadyRead)
	{
		CString csSquareCorners = GetStringDataFromIni(_T("SquareCorners"));
		csSquareCorners.Remove(_T('\t'));
		csSquareCorners.Trim();
		if(csSquareCorners == _T("1"))
		{
			bSquareCorners = true;
		}
		bAlreadyRead = true;
	}
	return bSquareCorners;
}

UINT CProductInfo::GetColorDataFromIni(TCHAR *csVal)
{
	UINT iColorValue;
	iColorValue = GetPrivateProfileInt(COLOR_VAL_INI, csVal, 0, m_csCurrentSettingIniPath);
	return iColorValue;
}
int CProductInfo::GetRectColor()
{
	m_iColorCode = (int)GetColorDataFromIni(_T("PRODUCT_RECTANGLE_COLOR"));
	return m_iColorCode;
}