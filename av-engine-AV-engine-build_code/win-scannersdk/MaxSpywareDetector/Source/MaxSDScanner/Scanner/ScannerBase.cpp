/*======================================================================================
FILE             : ScannerBase.cpp
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
CREATION DATE    : 8/1/2009 7:47:54 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "ScannerBase.h"
#include <time.h>
#include <io.h>
#include <atlbase.h>
#include "shlwapi.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CDBPathExpander CScannerBase::m_oDBPathExpander;
CCPUInfo CScannerBase::m_oCPUInfo;
CEnumProcess CScannerBase::m_oEnumProcess;
CRegistry CScannerBase::m_oRegistry;
CU2S CScannerBase::m_objFileValueType(false);
CU2S CScannerBase::m_objRegistryValueType(false);
CS2S CScannerBase::m_objAvailableUsers(false);
CRegistryHelper	CScannerBase::m_objRegHelper;
CRegPathExpander CScannerBase::m_objRegPathExp;

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::CScannerBase
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CScannerBase::CScannerBase():m_lpSendMessaegToUI(NULL), m_bStopScanning(false), m_bDeepScan(false), m_bUSBScan(false)
{
	m_bScanReferences = false;
	m_bRegFixForOptionTab = false;
	m_bStatusBar = false;
	if(m_objFileValueType.GetFirst() == NULL)
	{
		LoadFileValuePath();
	}

	if(m_objRegistryValueType.GetFirst() == NULL)
	{
		LoadRegistryValuePath();
	}

	m_objRegHelper.LoadAvailableUsers(m_objAvailableUsers);
	CallToStatusBarFucn();
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::~CScannerBase
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CScannerBase::~CScannerBase(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::EnumSubKeys
In Parameters  : CString csMainKey, CS2U &objSubKeyArr, HKEY hHiveKey, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CScannerBase::EnumSubKeys(CString csMainKey, CS2U &objSubKeyArr, HKEY hHiveKey)
{
	HKEY hMainkey = NULL;
	if(RegOpenKeyEx(hHiveKey, csMainKey, 0, KEY_READ, &hMainkey) != ERROR_SUCCESS)
	{
		return false;
	}

	DWORD LengthOfLongestSubkeyName = 0;
	DWORD dwSubKeyCount = 0;			// number of subkeys 

	//To detemine MAX length
	if(RegQueryInfoKey(hMainkey, NULL, NULL, NULL, &dwSubKeyCount, &LengthOfLongestSubkeyName, 
							NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
	{
		RegCloseKey( hMainkey);
		return false;
	}

	DWORD  LengthOfKeyName = LengthOfLongestSubkeyName;
	LPWSTR lpKeyName = NULL;

	lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR));
	if ( NULL == lpKeyName )
	{
		RegCloseKey( hMainkey);
		return false;
	}

	DWORD idxKey = 0, NTr = 0;

	for(idxKey = 0; idxKey < dwSubKeyCount ;idxKey++)
	{
		LengthOfKeyName = LengthOfLongestSubkeyName + 1;
		SecureZeroMemory(lpKeyName, (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR));
		NTr = RegEnumKeyEx(hMainkey, idxKey, (LPWSTR)lpKeyName, &LengthOfKeyName, NULL, NULL, NULL, NULL);

		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		// ignore entry which could not be retrieved as the buffer provided was small
		else if(NTr == ERROR_MORE_DATA) 
		{
			continue;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}
		else if(NTr == ERROR_SUCCESS)
		{
			if(LengthOfKeyName == 0)
			{
				continue;
			}

			if(LengthOfKeyName > MAX_PATH)
			{
				continue;
			}
			objSubKeyArr.AppendItem(lpKeyName, 0);
		}
	}

	GlobalFree(lpKeyName);
	RegCloseKey(hMainkey);

	if(objSubKeyArr.GetFirst() == NULL)
	{
		return false;
	}
	else
	{
		return true;
	}
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6386)
#endif

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::EnumValues
In Parameters  : CString csMainKey, vector<REG_VALUE_DATA> &vecRegValues, HKEY hHiveKey, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::EnumValues(CString csMainKey, vector<REG_VALUE_DATA> &vecRegValues, HKEY hHiveKey)
{
	DWORD LengthOfLongestValueName = 0;
	DWORD LengthOfLongestValueData = 0;
	DWORD TypeCode = 0;
	DWORD LengthOfValueName = 0;
	DWORD LengthOfValueData = 0;
	LPWSTR lpValueName = NULL;
	LPBYTE lpValueData = NULL;
	REG_VALUE_DATA objData = {0};

	HKEY hSubkey = NULL;
	if(RegOpenKeyEx(hHiveKey, csMainKey, 0, KEY_READ, &hSubkey) != ERROR_SUCCESS)
	{
		return;
	}

	if(RegQueryInfoKey(hSubkey, 0, 0, 0, 0, 0, 0, 0, &LengthOfLongestValueName, 
						&LengthOfLongestValueData, 0, 0) != ERROR_SUCCESS)
	{
		RegCloseKey ( hSubkey ) ;
		return ;
	}

	if(!LengthOfLongestValueName && !LengthOfLongestValueData)
	{
		RegCloseKey ( hSubkey ) ;
		return ;
	}

	LengthOfLongestValueName += sizeof(TCHAR);	
	LengthOfLongestValueData ++;

	lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueName * sizeof(TCHAR));
	lpValueData = (LPBYTE)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueData);
	if(NULL == lpValueName || NULL == lpValueData)
	{
		if(lpValueName)
		{
			GlobalFree(lpValueName);
		}
		if(lpValueData)
		{
			GlobalFree(lpValueData);
		}
		RegCloseKey(hSubkey);
		return;
	}

	for(DWORD iValIdx = 0; ; iValIdx++)
	{
		wmemset(lpValueName, 0, LengthOfLongestValueName);
		memset(lpValueData, 0, LengthOfLongestValueData);
		LengthOfValueName	=	LengthOfLongestValueName;
		LengthOfValueData	=	LengthOfLongestValueData;

		DWORD NTr = RegEnumValue(hSubkey, iValIdx, lpValueName, &LengthOfValueName, NULL, &TypeCode,
									lpValueData, &LengthOfValueData);

		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}

		if(LengthOfValueName >= _countof(objData.strValue))
		{
			continue;
		}

		if(LengthOfValueData > sizeof(objData.bData))
		{
			continue;
		}

		memset ( &objData , 0 , sizeof ( REG_VALUE_DATA ) ) ;
		objData.Type_Of_Data = TypeCode;
		objData.iSizeOfData = LengthOfValueData;
		wcscpy_s ( objData . strValue , lpValueName ) ;
		memcpy_s ( objData . bData , sizeof ( objData . bData ) , lpValueData , LengthOfValueData ) ;

		vecRegValues.push_back(objData);
	}

	GlobalFree(lpValueName);
	GlobalFree(lpValueData);
	RegCloseKey(hSubkey);
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6386)
#endif
/*--------------------------------------------------------------------------------------
Function       : CScannerBase::QueryRegData
In Parameters  : LPCWSTR strKeyPath, LPCWSTR strValueName, DWORD &dwDataType, LPBYTE lpbData,
					DWORD &dwBuffSize, HKEY HiveRoot, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CScannerBase::QueryRegData(LPCWSTR strKeyPath, LPCWSTR strValueName, DWORD &dwDataType,
								LPBYTE lpbData, DWORD &dwBuffSize, HKEY HiveRoot)
{
	DWORD dwSize = MAX_PATH;
	HKEY hKey = NULL;
	DWORD dwType = REG_SZ;

	if(::RegOpenKeyEx(HiveRoot, strKeyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		return false;
	}

	LONG lReturn = RegQueryValueEx(hKey, strValueName, NULL, &dwType, NULL, &dwSize);
	if(lReturn != ERROR_SUCCESS)
	{
		::RegCloseKey(hKey);
		return false;
	}

	if(((dwType != REG_SZ) && (dwType != REG_EXPAND_SZ) && (dwType != REG_MULTI_SZ) && (dwType != REG_DWORD)) || (dwSize == 0))
	{
		::RegCloseKey(hKey);
		return false;
	}

	LPBYTE pData = new BYTE[dwSize];
	memset(pData, 0, dwSize);
	lReturn = RegQueryValueEx(hKey, strValueName, NULL, &dwType, pData, &dwSize);
	if(lReturn != ERROR_SUCCESS)
	{
		::RegCloseKey(hKey);
		return false;
	}
	::RegCloseKey(hKey);

	dwDataType = dwType;
	if(dwBuffSize > dwSize)
	{
		memcpy_s(lpbData, dwBuffSize, pData, dwSize); 	//the size of pData is in BYTE's
		dwBuffSize = dwSize;
	}
	else
	{
		dwBuffSize = 0;
	}

	delete [] pData;
	pData = NULL;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::LoadFileValuePath
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::LoadFileValuePath()
{
	if(m_oDBPathExpander.m_cs501.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(501, m_oDBPathExpander.m_cs501);
	}
	if(m_oDBPathExpander.m_cs502.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(502, m_oDBPathExpander.m_cs502);
	}
	if(m_oDBPathExpander.m_cs503.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(503, m_oDBPathExpander.m_cs503);
	}
	if(m_oDBPathExpander.m_cs504.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(504, m_oDBPathExpander.m_cs504);
	}
	if(m_oDBPathExpander.m_cs505.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(505, m_oDBPathExpander.m_cs505);
	}
	if(m_oDBPathExpander.m_cs506.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(506, m_oDBPathExpander.m_cs506);
	}
	if(m_oDBPathExpander.m_cs507.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(507, m_oDBPathExpander.m_cs507);
	}
	if(m_oDBPathExpander.m_cs508.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(508, m_oDBPathExpander.m_cs508);
	}
	if(m_oDBPathExpander.m_cs509.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(509, m_oDBPathExpander.m_cs509);
	}
	if(m_oDBPathExpander.m_cs510.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(510, m_oDBPathExpander.m_cs510);
	}
	if(m_oDBPathExpander.m_cs511.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(511, m_oDBPathExpander.m_cs511);
	}
	if(m_oDBPathExpander.m_cs512.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(512, m_oDBPathExpander.m_cs512);
	}
	if(m_oDBPathExpander.m_cs513.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(513, m_oDBPathExpander.m_cs513);
	}
	if(m_oDBPathExpander.m_cs514.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(514, m_oDBPathExpander.m_cs514);
	}
	if(m_oDBPathExpander.m_cs515.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(515, m_oDBPathExpander.m_cs515);
	}
	if(m_oDBPathExpander.m_cs516.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(516, m_oDBPathExpander.m_cs516);
	}
	if(m_oDBPathExpander.m_cs517.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(517, m_oDBPathExpander.m_cs517);
	}
	if(m_oDBPathExpander.m_cs518.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(518, m_oDBPathExpander.m_cs518);
	}
	if(m_oDBPathExpander.m_cs519.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(519, m_oDBPathExpander.m_cs519);
	}
	if(m_oDBPathExpander.m_cs520.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(520, m_oDBPathExpander.m_cs520);
	}
	if(m_oDBPathExpander.m_cs521.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(521, m_oDBPathExpander.m_cs521);
	}
	if(m_oDBPathExpander.m_cs522.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(522, m_oDBPathExpander.m_cs522);
	}
	if(m_oDBPathExpander.m_cs523.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(523, m_oDBPathExpander.m_cs523);
	}
	if(m_oDBPathExpander.m_cs524.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(524, m_oDBPathExpander.m_cs524);
	}
	if(m_oDBPathExpander.m_cs525.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(525, m_oDBPathExpander.m_cs525);
	}
	if(m_oDBPathExpander.m_cs526.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(526, m_oDBPathExpander.m_cs526);
	}
	if(m_oDBPathExpander.m_cs527.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(527, m_oDBPathExpander.m_cs527);
	}
	if(m_oDBPathExpander.m_cs528.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(528, m_oDBPathExpander.m_cs528);
	}
	if(m_oDBPathExpander.m_cs529.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(529, m_oDBPathExpander.m_cs529);
	}
	if(m_oDBPathExpander.m_cs530.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(530, m_oDBPathExpander.m_cs530);
	}
	if(m_oDBPathExpander.m_cs531.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(531, m_oDBPathExpander.m_cs531);
	}
	if(m_oDBPathExpander.m_cs532.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(532, m_oDBPathExpander.m_cs532);
	}
	if(m_oDBPathExpander.m_cs533.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(533, m_oDBPathExpander.m_cs533);
	}
	if(m_oDBPathExpander.m_cs534.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(534, m_oDBPathExpander.m_cs534);
	}
	if(m_oDBPathExpander.m_cs535.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(535, m_oDBPathExpander.m_cs535);
	}
	if(m_oDBPathExpander.m_cs536.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(536, m_oDBPathExpander.m_cs536);
	}
	if(m_oDBPathExpander.m_cs537.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(537, m_oDBPathExpander.m_cs537);
	}
	if(m_oDBPathExpander.m_cs538.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(538, m_oDBPathExpander.m_cs538);
	}
	if(m_oDBPathExpander.m_cs539.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(539, m_oDBPathExpander.m_cs539);
	}
	if(m_oDBPathExpander.m_cs540.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(540, m_oDBPathExpander.m_cs540);
	}
	if(m_oDBPathExpander.m_cs541.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(541, m_oDBPathExpander.m_cs541);
	}
	if(m_oDBPathExpander.m_cs542.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(542, m_oDBPathExpander.m_cs542);
	}
	if(m_oDBPathExpander.m_cs543.GetLength() > 0)
	{
		m_objFileValueType.AppendItemAscOrder(543, m_oDBPathExpander.m_cs543);
	}

	m_objFileValueType.Balance();
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::CallToStatusBarFucn()
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : 
--------------------------------------------------------------------------------------*/
void CScannerBase::CallToStatusBarFucn()
{
	CRegistry objReg;
	DWORD dwStatusbar;

	dwStatusbar = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("StatusBar"),dwStatusbar, HKEY_LOCAL_MACHINE);
	if(dwStatusbar)
	{
		m_bStatusBar = true;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::LoadRegistryValuePath
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::LoadRegistryValuePath()
{
	m_objRegistryValueType.AppendItem(1, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\");
	m_objRegistryValueType.AppendItem(2, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\");
	m_objRegistryValueType.AppendItem(3, L"Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\");
	m_objRegistryValueType.AppendItem(4, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\");
	m_objRegistryValueType.AppendItem(5, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\");
	m_objRegistryValueType.AppendItem(6, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEX\\");
	m_objRegistryValueType.AppendItem(7, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\\");
	m_objRegistryValueType.AppendItem(8, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\\");
	m_objRegistryValueType.AppendItem(9, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\");
	m_objRegistryValueType.AppendItem(10, L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\");
	m_objRegistryValueType.AppendItem(11, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shareddlls\\");
	m_objRegistryValueType.AppendItem(12, L"Software\\Microsoft\\Windows\\CurrentVersion\\App Management\\Arpcache\\");
	m_objRegistryValueType.AppendItem(13, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\");
	m_objRegistryValueType.AppendItem(14, L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\");
	m_objRegistryValueType.AppendItem(15, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\");
	m_objRegistryValueType.AppendItem(16, L"Software\\Microsoft\\Windows\\CurrentVersion\\");
	m_objRegistryValueType.AppendItem(17, L"Software\\Microsoft\\Windows\\");
	m_objRegistryValueType.AppendItem(18, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\");
	m_objRegistryValueType.AppendItem(19, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\WinLogon\\Notify\\");
	m_objRegistryValueType.AppendItem(20, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\");
	m_objRegistryValueType.AppendItem(21, L"Software\\Microsoft\\Windows NT\\");
	m_objRegistryValueType.AppendItem(22, L"Software\\Microsoft\\Code Store Database\\Application Namespaces\\");
	m_objRegistryValueType.AppendItem(23, L"Software\\Microsoft\\Code Store Database\\Distribution Units\\");
	m_objRegistryValueType.AppendItem(24, L"Software\\Microsoft\\Code Store Database\\Global Namespace\\");
	m_objRegistryValueType.AppendItem(25, L"Software\\Microsoft\\Internet Explorer\\Extensions\\");
	m_objRegistryValueType.AppendItem(26, L"Software\\Microsoft\\Internet Explorer\\Toolbar\\");
	m_objRegistryValueType.AppendItem(27, L"Software\\Microsoft\\Internet Explorer\\Toolbar\\Explorer\\");
	m_objRegistryValueType.AppendItem(28, L"Software\\Microsoft\\Internet Explorer\\Toolbar\\ShellBrowser\\");
	m_objRegistryValueType.AppendItem(29, L"Software\\Microsoft\\Internet Explorer\\Toolbar\\WebBrowser\\");
	m_objRegistryValueType.AppendItem(30, L"Software\\Microsoft\\");
	m_objRegistryValueType.AppendItem(31, L"Software\\Classes\\Interface\\");
	m_objRegistryValueType.AppendItem(32, L"Software\\Classes\\Clsid\\");
	m_objRegistryValueType.AppendItem(33, L"Software\\Classes\\Typelib\\");
	m_objRegistryValueType.AppendItem(34, L"Software\\Classes\\Installer\\");
	m_objRegistryValueType.AppendItem(35, L"Software\\Classes\\Software\\");
	m_objRegistryValueType.AppendItem(36, L"Software\\Classes\\Appid\\");
	m_objRegistryValueType.AppendItem(37, L"Software\\Classes\\");
	m_objRegistryValueType.AppendItem(38, L"Software\\");
	m_objRegistryValueType.AppendItem(39, L"System\\CurrentControlSet\\Services\\");
	m_objRegistryValueType.AppendItem(40, L"System\\CurrentControlSet\\Enum\\");
	m_objRegistryValueType.AppendItem(41, L"System\\CurrentControlSet\\Hardware Profiles\\");
	m_objRegistryValueType.AppendItem(42, L"System\\CurrentControlSet\\Control\\");
	m_objRegistryValueType.AppendItem(43, L"System\\");

	m_objRegistryValueType.Balance();
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::SendScanStatusToUI
In Parameters  : PMAX_SCANNER_INFO pScannerInfo, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 June, 2011.
--------------------------------------------------------------------------------------*/
void CScannerBase::SendScanStatusToUI(PMAX_SCANNER_INFO pScannerInfo)
{
	if(m_lpSendMessaegToUI && pScannerInfo)
	{
		PMAX_SCANNER_INFO pHoldScanInfo = pScannerInfo;

		while(pScannerInfo)
		{
			if((!pScannerInfo->IsChildFile) && ((pScannerInfo->ThreatDetected == 1) || (pScannerInfo->ThreatSuspicious == 1)))
			{
				eEntry_Status eStatue = (pScannerInfo->ThreatQuarantined ? eStatus_Quarantined : ((pScannerInfo->ThreatRepaired ? eStatus_Repaired : ((pScannerInfo->ThreatNonCurable ? eStatus_Detected : ((pScannerInfo->ThreatDetected ? eStatus_Detected : ((pScannerInfo->ThreatSuspicious ? eStatus_Detected : (eStatus_NotApplicable))))))))));

				if(Detected_BY_MaxAVModule == pScannerInfo->eDetectedBY)
				{
					m_lpSendMessaegToUI(pScannerInfo->eMessageInfo, eStatue, pScannerInfo->ulThreatID, (HKEY)pScannerInfo->eDetectedBY, pScannerInfo->szFileToScan, pScannerInfo->szContainerFileName, 0, 0, 0, 0, 0, 0, pScannerInfo);
				}
				else
				{
					m_lpSendMessaegToUI(pScannerInfo->eMessageInfo, eStatue, pScannerInfo->ulThreatID, (HKEY)pScannerInfo->eDetectedBY, pScannerInfo->szFileToScan, pScannerInfo->szThreatName, 0, 0, 0, 0, 0, 0, pScannerInfo);
				}
			}

			pScannerInfo = pScannerInfo->pNextScanInfo;
		}

		if(pHoldScanInfo->pNextScanInfo && pHoldScanInfo->FreeNextScanInfo)
		{
			pScannerInfo = pHoldScanInfo;
			pHoldScanInfo = pHoldScanInfo->pNextScanInfo;
			pScannerInfo->pNextScanInfo = NULL;
			pScannerInfo->FreeNextScanInfo = false;
			while(pHoldScanInfo)
			{
				pScannerInfo = pHoldScanInfo->pNextScanInfo;
				if(pHoldScanInfo->IsChildFile)
				{
					::DeleteFile(pHoldScanInfo->szFileToScan);
				}
				delete pHoldScanInfo;
				pHoldScanInfo = pScannerInfo;
			}
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::SendScanStatusToUI
In Parameters  : SD_Message_Info eTypeOfScanner, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::SendScanStatusToUI(SD_Message_Info eTypeOfScanner)
{
	if(m_lpSendMessaegToUI)
	{
		m_lpSendMessaegToUI(eTypeOfScanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::SendScanStatusToUI
In Parameters  : SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const TCHAR *strValue, 
					const TCHAR *strSignature, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, 
									  const TCHAR *strValue, const TCHAR *strSignature)
{
	if(m_lpSendMessaegToUI)
	{
		m_lpSendMessaegToUI(eTypeOfScanner, eStatus_Detected, ulSpyName, 0, strValue, 0, 0, 0, 0, 0, 0, 0, 0);
	}
	if ((eTypeOfScanner != FilePath_Report) && (eTypeOfScanner != ExecPath) && (eTypeOfScanner != Module) && (eTypeOfScanner != Module_Report) && (eTypeOfScanner != Virus_File) && (eTypeOfScanner != Virus_File_Repair))
	{
		AddLogEntry(eTypeOfScanner, strValue, strSignature);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::SendScanStatusToUI
In Parameters  : SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const TCHAR *strKey,
					const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, 
					REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, 
									  const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, 
									  int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
									  int iSizeOfReplaceData)
{
	if(m_lpSendMessaegToUI)
	{
		m_lpSendMessaegToUI(eTypeOfScanner, eStatus_Detected, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data, lpbData, iSizeOfData, 
								psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData, 0);
	}

	if((!m_bRegFixForOptionTab) && (eTypeOfScanner != Status_Bar_File) && (eTypeOfScanner != Status_Bar_File_Report))
	{
		AddLogEntry(eTypeOfScanner, strKey, strValue, Type_Of_Data, (LPCTSTR)lpbData, (LPCTSTR)lpbReplaceData);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::GetOtherValueTypeID
In Parameters  : ULONG lValueTypeID, 
Out Parameters : ULONG 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
ULONG CScannerBase::GetOtherValueTypeID(ULONG lValueTypeID)
{
	switch(lValueTypeID)
	{
	case 504:
	case 509:
		{
			return (lValueTypeID == 504 ? 509 : 504);
		}
	case 505:
	case 513:
		{
			return (lValueTypeID == 505 ? 513 : 505);
		}
	case 506:
	case 514:
		{
			return (lValueTypeID == 506 ? 514 : 506);
		}
	case 507:
	case 515:
		{
			return (lValueTypeID == 507 ? 515 : 507);
		}
	case 508:
	case 516:
		{
			return (lValueTypeID == 508 ? 516 : 508);
		}
	}
	return 0;
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6386)
#endif

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::PreparePESigForLog
In Parameters  : WCHAR *wcsPE, int iBuffSize, LPBYTE PrimSign, LPBYTE SecSign, LPDWORD pdwIndex
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::PreparePESigForLog(WCHAR *wcsPE, int iBuffSize, LPBYTE PrimSign, LPBYTE SecSign, LPDWORD pdwIndex)
{
	swprintf_s(wcsPE, iBuffSize, L"%8u:%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x", 
		*pdwIndex,
		PrimSign[0], PrimSign[1], PrimSign[2], PrimSign[3], 
		PrimSign[4], PrimSign[5], PrimSign[6], PrimSign[7], 
		SecSign[0], SecSign[1], SecSign[2], SecSign[3],
		SecSign[4], SecSign[5], SecSign[6], SecSign[7]);
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::PrepareMD5ForLog
In Parameters  : WCHAR *wcsMD5, int iBuffSize, STRUCT_LOCAL_DB *pstLocalDB, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CScannerBase::PrepareMD5ForLog(WCHAR *wcsMD5, int iBuffSize, LPBYTE MD5Signature, LPDWORD pdwIndex)
{
	swprintf_s(wcsMD5, iBuffSize, L"%8u:%02x%02x%02x%02x%02x%02x%02x%02x", 
		*pdwIndex,
		MD5Signature[0], MD5Signature[1], MD5Signature[2], MD5Signature[3],
		MD5Signature[4], MD5Signature[5], MD5Signature[6], MD5Signature[7]);
}

/*--------------------------------------------------------------------------------------
Function       : SetFullLiveUpdateReg
In Parameters  : TCHAR * szFile, 
Out Parameters : void 
Description    : 
Author         : Sandip
--------------------------------------------------------------------------------------*/
void CScannerBase::SetFullLiveUpdateReg(LPCTSTR szFile)
{
	AddLogEntry(_T("Scanning skip for database : %s"), szFile);
	m_oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6386)
#endif