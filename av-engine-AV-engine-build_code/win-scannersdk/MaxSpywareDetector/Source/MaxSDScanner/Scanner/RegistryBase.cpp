/*======================================================================================
FILE             : RegistryBase.cpp
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
				  
CREATION DATE    : 8/1/2009 7:26:23 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include <atlbase.h>
#include "RegistryBase.h"
#include "RegFix.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::CRegistryBase
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CRegistryBase::CRegistryBase(void):m_oDuplicateRegFixEntry(false)
{
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::~CRegistryBase
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CRegistryBase::~CRegistryBase(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartAppInitScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartAppInitScan()
{
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	CS2U objAppInitDBMap(false);
	objAppInitDBMap.Load(csMaxDBPath + SD_DB_APPINIT_DLL);
	if(objAppInitDBMap.GetFirst() != NULL)
	{
		ScanAppInitDataPart(objAppInitDBMap, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
#ifdef WIN64
		ScanAppInitDataPart(objAppInitDBMap, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
#endif
		objAppInitDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_APPINIT_DLL);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanAppInitDataPart
In Parameters  : CS2U &objDBMap, LPCWSTR lstrRegistryPath, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanAppInitDataPart(CS2U &objDBMap, LPCWSTR lstrRegistryPath)
{
	DWORD dwDataType = 0;
	BYTE bSystemData[MAX_PATH*4] = {0};
	DWORD dwBuffSize = MAX_PATH*4;
	if(QueryRegData(lstrRegistryPath, L"AppInit_DLLs", dwDataType, bSystemData, dwBuffSize, HKEY_LOCAL_MACHINE))
	{
		if((dwBuffSize > 2) && (dwDataType == REG_SZ))
		{
			CString csSysValue((LPCTSTR)bSystemData);
			csSysValue = m_oDBPathExpander.ExpandSystemPath(csSysValue);
			LPVOID lpVoid = objDBMap.GetFirst();
			while(lpVoid && !m_bStopScanning)
			{
				LPTSTR lpDBValue = NULL;
				objDBMap.GetKey(lpVoid, lpDBValue);
				CString csFullPath = m_oDBPathExpander.ExpandPath(lpDBValue, L"");
				if(csSysValue.Find(csFullPath) != -1)
				{
					DWORD ulSpyName = 0;
					objDBMap.GetData(lpVoid, ulSpyName);
					SendScanStatusToUI(AppInit, ulSpyName, HKEY_LOCAL_MACHINE, lstrRegistryPath, 
										L"AppInit_DLLs", dwDataType, bSystemData, dwBuffSize, 0, 
										(LPBYTE)(LPCTSTR)csFullPath, 
										(csFullPath.GetLength()*sizeof(TCHAR))+sizeof(TCHAR));
				}
				lpVoid = objDBMap.GetNext(lpVoid);
			}
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartBHOScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartBHOScan()
{
	CS2U objBHODBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objBHODBMap.Load(csMaxDBPath + SD_DB_BHO);
	if(objBHODBMap.GetFirst() != NULL)
	{
		ScanUsingDBByEnrtyNSpyID(objBHODBMap, 
				L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\", 
				BHO);
#ifdef WIN64
		ScanUsingDBByEnrtyNSpyID(objBHODBMap, 
				L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\", 
				BHO);
#endif
		objBHODBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_BHO);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartActiveXScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartActiveXScan()
{
	CS2U objActiveXDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objActiveXDBMap.Load(csMaxDBPath + SD_DB_ACTIVEX);
	if(objActiveXDBMap.GetFirst() != NULL)
	{
		ScanUsingDBByEnrtyNSpyID(objActiveXDBMap, 
								L"Software\\Microsoft\\Code Store Database\\Distribution Units\\", 
								ActiveX);
#ifdef WIN64
		ScanUsingDBByEnrtyNSpyID(objActiveXDBMap, 
								L"Software\\Wow6432Node\\Microsoft\\Code Store Database\\Distribution Units\\", 
								ActiveX);
#endif
		objActiveXDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_ACTIVEX);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartMenuExtScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartMenuExtScan()
{
	CS2U objMenuExtDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objMenuExtDBMap.Load(csMaxDBPath + SD_DB_MENUEXT);
	if(objMenuExtDBMap.GetFirst() != NULL)
	{
		ScanUsingDBByEnrtyNSpyID(objMenuExtDBMap, 
								L"Software\\Microsoft\\Internet Explorer\\Extensions\\", 
								MenuExt_Key);
#ifdef WIN64
		ScanUsingDBByEnrtyNSpyID(objMenuExtDBMap, 
								L"Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Extensions\\", 
								MenuExt_Key);
#endif
		AddLogEntry(Starting_MenuExt_Key_Scanner, L"MenuExt Key Scan", 0, 0, 0, 0, false);
		AddLogEntry(Starting_MenuExt_Value_Scanner, L"MenuExt Value Scan");
		SendScanStatusToUI(Starting_MenuExt_Value_Scanner);
		ScanProfilePathUsingDBByEnrtyNSpyID(objMenuExtDBMap, 
								L"Software\\Microsoft\\Internet Explorer\\Extensions\\CmdMapping\\", 
								MenuExt_Value, false);
#ifdef WIN64
		ScanProfilePathUsingDBByEnrtyNSpyID(objMenuExtDBMap, 
								L"Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Extensions\\CmdMapping\\", 
								MenuExt_Value, false);
#endif
		objMenuExtDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_MENUEXT);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartRunScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartRunScan()
{
	CS2U objRunDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objRunDBMap.Load(csMaxDBPath + SD_DB_RUN);
	if(objRunDBMap.GetFirst() != NULL)
	{
		CStringArray arrRegPath;
		arrRegPath.Add(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\");
		arrRegPath.Add(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\");
		arrRegPath.Add(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\");
		arrRegPath.Add(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\\");
		arrRegPath.Add(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\\");
#ifdef WIN64
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\\");
#endif
		ScanProfilePathUsingDBByEnrtyNSpyIDArray(objRunDBMap, arrRegPath, Run1, true);
		objRunDBMap.RemoveAll();
		arrRegPath.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_RUN);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartTooBarScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartTooBarScan()
{
	CS2U objToolBarDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objToolBarDBMap.Load(csMaxDBPath + SD_DB_TOOLBAR);
	if(objToolBarDBMap.GetFirst() != NULL)
	{
		CStringArray arrRegPath;
		arrRegPath.Add(L"Software\\Microsoft\\Internet Explorer\\Toolbar\\");
		arrRegPath.Add(L"Software\\Microsoft\\Internet Explorer\\Toolbar\\Explorer\\");
		arrRegPath.Add(L"Software\\Microsoft\\Internet Explorer\\Toolbar\\ShellBrowser\\");
		arrRegPath.Add(L"Software\\Microsoft\\Internet Explorer\\Toolbar\\WebBrowser\\");
#ifdef WIN64
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\Explorer\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\ShellBrowser\\");
		arrRegPath.Add(L"Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\WebBrowser\\");
#endif
		ScanProfilePathUsingDBByEnrtyNSpyIDArray(objToolBarDBMap, arrRegPath, Toolbar, false);
		objToolBarDBMap.RemoveAll();
		arrRegPath.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_TOOLBAR);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartRegKeyScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartRegKeyScan()
{
	CU2OU2O objRegKeyDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objRegKeyDBMap.Load(csMaxDBPath + SD_DB_REGKEY);
	if(objRegKeyDBMap.GetFirst() != NULL)
	{
		ScanUsingRegKeyDB(objRegKeyDBMap);
		objRegKeyDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_REGKEY);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartRegValScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartRegValScan()
{
	CUUSSU objRegValDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objRegValDBMap.Load(csMaxDBPath + SD_DB_REGVAL);
	if(objRegValDBMap.GetFirst() != NULL)
	{
		ScanUsingRegValDB(objRegValDBMap);
		objRegValDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_REGVAL);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartServicesScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartServicesScan()
{
    CS2U objServicesDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objServicesDBMap.Load(csMaxDBPath + SD_DB_SERVICES);
	if(objServicesDBMap.GetFirst() != NULL)
	{
		ScanUsingDBByEnrtyNSpyID(objServicesDBMap, L"System\\CurrentControlSet\\Services\\", Service);
		objServicesDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_SERVICES);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartSSODLScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartSSODLScan()
{
    CS2U objSSODLDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objSSODLDBMap.Load(csMaxDBPath + SD_DB_SSODLREG);
	if(objSSODLDBMap.GetFirst() != NULL)
	{
        ScanProfilePathUsingDBByEnrtyNSpyID(objSSODLDBMap, 
							L"Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\", 
							SSODL, true);        
#ifdef WIN64
        ScanProfilePathUsingDBByEnrtyNSpyID(objSSODLDBMap, 
							L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\", 
							SSODL, true);        
#endif
    	objSSODLDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_SSODLREG);
	}
}

void CRegistryBase::StartSharedTaskScan()
{
    CS2U objSharedTaskDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objSharedTaskDBMap.Load(csMaxDBPath + SD_DB_SHARED_TASK);
	if(objSharedTaskDBMap.GetFirst() != NULL)
	{
        ScanProfilePathUsingDBByEnrtyNSpyID(objSharedTaskDBMap, 
						L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\", 
						SharedTask, true);        
#ifdef WIN64
        ScanProfilePathUsingDBByEnrtyNSpyID(objSharedTaskDBMap, 
						L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\", 
						SharedTask, true);        
#endif
 		objSharedTaskDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_SHARED_TASK);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartNotifyScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartNotifyScan()
{
	CS2U objNotifyDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objNotifyDBMap.Load(csMaxDBPath + SD_DB_NOTIFY);
	if(objNotifyDBMap.GetFirst() != NULL)
	{
		ScanUsingDBByEnrtyNSpyID(objNotifyDBMap, 
								L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\", 
								Notify);
#ifdef WIN64
		ScanUsingDBByEnrtyNSpyID(objNotifyDBMap, 
								L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\", 
								Notify);
#endif
		objNotifyDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_NOTIFY);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartSharedDllScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartSharedDllScan()
{
	CS2U objSharedDllDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objSharedDllDBMap.Load(csMaxDBPath + SD_DB_SHARED_DLLS);
	if(objSharedDllDBMap.GetFirst() != NULL)
	{
		ScanRegistryValue(L"Software\\Microsoft\\Windows\\CurrentVersion\\Shareddlls", 
							HKEY_LOCAL_MACHINE, objSharedDllDBMap, SharedDlls, true);
#ifdef WIN64
		ScanRegistryValue(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Shareddlls", 
							HKEY_LOCAL_MACHINE, objSharedDllDBMap, SharedDlls, true);
#endif
		objSharedDllDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_SHARED_DLLS);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartShellExecuteHooksScan
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartShellExecuteHooksScan()
{
	CS2U objShellExecuteHooksDBMap(false);
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objShellExecuteHooksDBMap.Load(csMaxDBPath + SD_DB_SHELLEXECUTEHOOKS);
	if(objShellExecuteHooksDBMap.GetFirst() != NULL)
	{
		ScanRegistryValue(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", 
							HKEY_LOCAL_MACHINE, objShellExecuteHooksDBMap, ShellExecuteHooks, true);
#ifdef WIN64
		ScanRegistryValue(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", 
							HKEY_LOCAL_MACHINE, objShellExecuteHooksDBMap, ShellExecuteHooks, true);
#endif
		objShellExecuteHooksDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_SHELLEXECUTEHOOKS);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanProfilePathUsingDBByEnrtyNSpyIDArray
In Parameters  : CS2U &objDBMap, CStringArray &arrRegPath, SD_Message_Info eTypeOfScanner, bool bExpandPath, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanProfilePathUsingDBByEnrtyNSpyIDArray(CS2U &objDBMap, CStringArray &arrRegPath, 
															 SD_Message_Info eTypeOfScanner, bool bExpandPath)
{
	for(int iCtr = 0; iCtr < arrRegPath.GetCount(); iCtr++)
	{
		ScanRegistryValue(arrRegPath.GetAt(iCtr), HKEY_LOCAL_MACHINE, objDBMap, eTypeOfScanner, bExpandPath);
		LPVOID posUserName = m_objAvailableUsers.GetFirst();
		while(posUserName && !m_bStopScanning)
		{
			CString csUserSID;
			LPTSTR strUserSID = NULL;
			m_objAvailableUsers.GetKey(posUserName, strUserSID);
			csUserSID = strUserSID;
			csUserSID += L"\\";
			csUserSID += arrRegPath.GetAt(iCtr);
			ScanRegistryValue(csUserSID, HKEY_USERS, objDBMap, eTypeOfScanner, bExpandPath);
			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanProfilePathUsingDBByEnrtyNSpyID
In Parameters  : CS2U &objDBMap, LPCWSTR lstrRegistryPath, SD_Message_Info eTypeOfScanner, bool bExpandPath, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanProfilePathUsingDBByEnrtyNSpyID(CS2U &objDBMap, LPCWSTR lstrRegistryPath, 
														SD_Message_Info eTypeOfScanner, bool bExpandPath)
{
	if(eTypeOfScanner == SSODL)
	{
		ScanRegistryValueNData(lstrRegistryPath, HKEY_LOCAL_MACHINE, objDBMap, eTypeOfScanner, bExpandPath);
	}
	else
	{
		ScanRegistryValue(lstrRegistryPath, HKEY_LOCAL_MACHINE, objDBMap, eTypeOfScanner, bExpandPath);
	}
	LPVOID posUserName = m_objAvailableUsers.GetFirst();
	while(posUserName && !m_bStopScanning)
	{
		CString csUserSID;
		LPTSTR strUserSID = NULL;
		m_objAvailableUsers.GetKey(posUserName, strUserSID);
		csUserSID = strUserSID;
		csUserSID += L"\\";
		csUserSID += lstrRegistryPath;
		if(eTypeOfScanner == SSODL)
		{
			ScanRegistryValueNData(csUserSID, HKEY_USERS, objDBMap, eTypeOfScanner, bExpandPath);
		}
		else
		{
			ScanRegistryValue(csUserSID, HKEY_USERS, objDBMap, eTypeOfScanner, bExpandPath);
		}
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanRegistryValue
In Parameters  : LPCWSTR lstrRegPath, HKEY hHiveToScan, CS2U &objDBMap, 
					SD_Message_Info eTypeOfScanner, bool bExpandPath, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanRegistryValue(LPCWSTR lstrRegPath, HKEY hHiveToScan, CS2U &objDBMap, 
									SD_Message_Info eTypeOfScanner, bool bExpandPath)
{
	vector<REG_VALUE_DATA> vecRegValues;
	EnumValues(lstrRegPath, vecRegValues, hHiveToScan);
	
	for(unsigned int iCtr = 0; iCtr < vecRegValues.size() && !m_bStopScanning; iCtr++)
	{
		CString csValue = vecRegValues[iCtr].strValue;
		csValue.MakeLower();
		if(bExpandPath)
		{
			if(m_oDBPathExpander.SplitPathByValueType(csValue))
			{
				csValue = m_oDBPathExpander.m_csValueTAG + m_oDBPathExpander.m_csValue;
			}
		}
		ULONG lSpyNameID = 0;
		if(objDBMap.SearchItem(csValue, &lSpyNameID))
		{
			bool bSafeToQuarantine = false, bIsFileFound = false;

			bSafeToQuarantine = SearchScannedFileFolderInValueData(vecRegValues[iCtr].strValue,
									vecRegValues[iCtr].Type_Of_Data,vecRegValues[iCtr].bData,
									bIsFileFound);
			if(bSafeToQuarantine || bIsFileFound)
			{
				SendScanStatusToUI(eTypeOfScanner, lSpyNameID, hHiveToScan, lstrRegPath, 
									vecRegValues[iCtr].strValue, vecRegValues[iCtr].Type_Of_Data, 
									vecRegValues[iCtr].bData, vecRegValues[iCtr].iSizeOfData, 0, 0, 0);
				if((eTypeOfScanner == Toolbar) || (eTypeOfScanner == SSODL) || 
					(eTypeOfScanner == MenuExt_Value)  || (eTypeOfScanner == ShellExecuteHooks))
				{
					m_objRegHelper.GetAllComEntries(csValue, lSpyNameID);
				}
			}
		}
	}
	if(vecRegValues.size() > 0)
	{
		vecRegValues.clear();
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanRegistryValueNData
In Parameters  : LPCWSTR lstrRegPath, HKEY hHiveToScan, CS2U &objDBMap, 
					SD_Message_Info eTypeOfScanner, bool bExpandPath, 
Out Parameters : void 
Description    : Scans the Registry Value and Data in the given db
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanRegistryValueNData(LPCWSTR lstrRegPath, HKEY hHiveToScan, CS2U &objDBMap, 
										SD_Message_Info eTypeOfScanner, bool bExpandPath)
{
	vector<REG_VALUE_DATA> vecRegValues;
	EnumValues(lstrRegPath, vecRegValues, hHiveToScan);
	
	for(unsigned int iCtr = 0; iCtr < vecRegValues.size() && !m_bStopScanning; iCtr++)
	{
		CString csValue = vecRegValues[iCtr].strValue;
		csValue.MakeLower();
		if(bExpandPath)
		{
			if(m_oDBPathExpander.SplitPathByValueType(csValue))
			{
				csValue = m_oDBPathExpander.m_csValueTAG + m_oDBPathExpander.m_csValue;
			}
		}
		ULONG lSpyNameID = 0;
		if(objDBMap.SearchItem(csValue, &lSpyNameID))
		{
			SendScanStatusToUI(eTypeOfScanner, lSpyNameID, hHiveToScan, lstrRegPath, 
								vecRegValues[iCtr].strValue, vecRegValues[iCtr].Type_Of_Data, 
								vecRegValues[iCtr].bData, vecRegValues[iCtr].iSizeOfData, 0, 0, 0);
            if((eTypeOfScanner == Toolbar) || (eTypeOfScanner == SSODL) || 
				(eTypeOfScanner == MenuExt_Value)  || (eTypeOfScanner == ShellExecuteHooks))
            {               
                m_objRegHelper.GetAllComEntries(csValue, lSpyNameID);
            }
		}
		else
		{
			ULONG lSpyNameID = 0;
			csValue = (LPCTSTR)vecRegValues[iCtr].bData;
			if(objDBMap.SearchItem(csValue, &lSpyNameID))
			{
				SendScanStatusToUI(eTypeOfScanner, lSpyNameID, hHiveToScan, lstrRegPath, 
									vecRegValues[iCtr].strValue, vecRegValues[iCtr].Type_Of_Data, 
									vecRegValues[iCtr].bData, vecRegValues[iCtr].iSizeOfData, 0, 0, 0);
				if((eTypeOfScanner == Toolbar) || (eTypeOfScanner == SSODL) || 
					(eTypeOfScanner == MenuExt_Value)  || (eTypeOfScanner == ShellExecuteHooks))
				{               
					m_objRegHelper.GetAllComEntries(csValue, lSpyNameID);
				}
			}
		}
	}
	if(vecRegValues.size() > 0)
	{
		vecRegValues.clear();
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanUsingDBByEnrtyNSpyID
In Parameters  : CS2U &objDBMap, LPCWSTR lstrRegistryPath, SD_Message_Info eTypeOfScanner, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanUsingDBByEnrtyNSpyID(CS2U &objDBMap, LPCWSTR lstrRegistryPath, SD_Message_Info eTypeOfScanner)
{
	CS2U arrSubKeys(false);
	EnumSubKeys(lstrRegistryPath, arrSubKeys, HKEY_LOCAL_MACHINE);

	LPVOID posEntry = arrSubKeys.GetFirst();
	while(posEntry && !m_bStopScanning)
	{
		CString csSubKey;
		LPTSTR strSubKey = NULL;
		arrSubKeys.GetKey(posEntry, strSubKey);
		csSubKey = strSubKey;
		csSubKey.MakeLower();
		ULONG lSpyNameID = 0;
		if(objDBMap.SearchItem(csSubKey, &lSpyNameID))
		{
			LPTSTR strKey = NULL;
			arrSubKeys.GetKey(posEntry, strKey);
			csSubKey.Format(L"%s%s", lstrRegistryPath, strSubKey);
			SendScanStatusToUI(eTypeOfScanner, lSpyNameID, HKEY_LOCAL_MACHINE, csSubKey, 0, 0, 0, 0, 0, 0, 0);
            m_objRegHelper.EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csSubKey, lSpyNameID);
            if((eTypeOfScanner == BHO) || (eTypeOfScanner == ActiveX) || (eTypeOfScanner == MenuExt_Key) )
            {               
                m_objRegHelper.GetAllComEntries(strSubKey, lSpyNameID);                
            }
		}
		posEntry = arrSubKeys.GetNext(posEntry);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanUsingRegKeyDB
In Parameters  : CU2OU2O &objDBMap, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanUsingRegKeyDB(CU2OU2O &objDBMap)
{
	LPVOID posProfType = objDBMap.GetFirst();
	while((!m_bStopScanning) && (posProfType))
	{
		ULONG lProfType = 0;
		objDBMap.GetKey(posProfType, lProfType);
		CU2OS2U oValueType(true);
		objDBMap.GetData(posProfType, oValueType);
		if(lProfType == 1)
		{
			ScanNonProfilePath(oValueType);
		}
		else if(lProfType == 2)
		{
			ScanProfilePath(oValueType);
		}
		else if(lProfType == 3)
		{
			ScanNonProfilePath(oValueType);
			ScanProfilePath(oValueType);
		}

		posProfType = objDBMap.GetNext(posProfType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanNonProfilePath
In Parameters  : CU2OS2U &oValueType, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanNonProfilePath(CU2OS2U &oValueType)
{
	LPVOID posValueType = oValueType.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		ULONG lValueTypeID = 0;
		oValueType.GetKey(posValueType, lValueTypeID);
		CS2U oValueNSpyID(true);
		oValueType.GetData(posValueType, oValueNSpyID);

		LPTSTR strValuePath = NULL;
		if(m_objRegistryValueType.SearchItem(lValueTypeID, &strValuePath))
		{
			ScanRegistryEntry(oValueNSpyID, strValuePath, HKEY_LOCAL_MACHINE, RegKey);
#ifdef WIN64
			if(strValuePath[6] != '\\')  // a slash at 6th location is only possible incase it's a System Entry
			{
				WCHAR strWow64ValuePath[MAX_PATH] = {0};
				wcscpy_s(strWow64ValuePath, MAX_PATH, L"Software\\Wow6432Node");
				wcscat_s(strWow64ValuePath, MAX_PATH, &strValuePath[8]); 
				ScanRegistryEntry(oValueNSpyID, strWow64ValuePath, HKEY_LOCAL_MACHINE, RegKey);
			}
#endif
		}

		posValueType = oValueType.GetNext(posValueType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanProfilePath
In Parameters  : CU2OS2U &oValueType, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanProfilePath(CU2OS2U &oValueType)
{
	LPVOID posValueType = oValueType.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		ULONG lValueTypeID = 0;
		oValueType.GetKey(posValueType, lValueTypeID);
		CS2U oValueNSpyID(true);
		oValueType.GetData(posValueType, oValueNSpyID);

		LPVOID posUserName = m_objAvailableUsers.GetFirst();
		while((!m_bStopScanning) && (posUserName))
		{
			LPTSTR strValuePath = NULL;
			if(m_objRegistryValueType.SearchItem(lValueTypeID, &strValuePath))
			{
				LPTSTR strUserSID = NULL;
				m_objAvailableUsers.GetKey(posUserName, strUserSID);

				ScanRegistryEntry(oValueNSpyID, strUserSID + CString(L"\\") + strValuePath, HKEY_USERS, RegKey);
#ifdef WIN64
				if(strValuePath[6] != '\\')  // a slash at 6th location is only possible incase it's a System Entry
				{
					WCHAR strWow64ValuePath[MAX_PATH] = {0};
					wcscpy_s(strWow64ValuePath, MAX_PATH, L"Software\\Wow6432Node");
					wcscat_s(strWow64ValuePath, MAX_PATH, &strValuePath[8]); 
					ScanRegistryEntry(oValueNSpyID, strUserSID + CString(L"\\") + strWow64ValuePath, HKEY_USERS, RegKey);
				}
#endif
			}
			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}
		posValueType = oValueType.GetNext(posValueType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanRegistryEntry
In Parameters  : CS2U &oValueNSpyID, const CString &csValuePath, HKEY hHiveToScan, 
					SD_Message_Info eTypeOfScanner, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanRegistryEntry(CS2U &oValueNSpyID, const CString &csValuePath, 
									  HKEY hHiveToScan, SD_Message_Info eTypeOfScanner)
{
	HKEY hParentKey = NULL;
	if(RegOpenKeyEx(hHiveToScan, csValuePath, 0, KEY_READ, &hParentKey) == ERROR_SUCCESS)
	{
		LPVOID posValueNSpyID = oValueNSpyID.GetFirst();
		while((!m_bStopScanning) && (posValueNSpyID))
		{
			LPTSTR strSubKey = NULL;
			oValueNSpyID.GetKey(posValueNSpyID, strSubKey);
			if(strSubKey)
			{
				ULONG lSpyNameID = 0;
				oValueNSpyID.GetData(posValueNSpyID, lSpyNameID);

				HKEY hChildKey = NULL;
				if(RegOpenKeyEx(hParentKey, strSubKey, 0, KEY_READ, &hChildKey) == ERROR_SUCCESS)
				{
					bool bChildHasScannedFileName = false, bIsFileFound = false;

					bChildHasScannedFileName = SearchScannedFileFolderInKey(hParentKey, strSubKey, bIsFileFound, lSpyNameID);
					if(bChildHasScannedFileName || bIsFileFound)
					{
						CString csFullKey;
						csFullKey.Format(_T("%s%s"), static_cast < LPCTSTR > ( csValuePath ) , strSubKey ) ;
						SendScanStatusToUI(eTypeOfScanner, lSpyNameID, hHiveToScan, (LPCTSTR)csFullKey, 0, 0, 0, 0, 0, 0, 0);
						RegCloseKey(hChildKey);
						m_objRegHelper.EnumKeyNReportToUI(hHiveToScan, csFullKey, lSpyNameID);
						if(eTypeOfScanner == RegKey)
						{               
							m_objRegHelper.GetAllComEntries(strSubKey, lSpyNameID);
						}
					}
				}
			}

			posValueNSpyID = oValueNSpyID.GetNext(posValueNSpyID);
		}
		RegCloseKey(hParentKey);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::StartRegFixScan
In Parameters  : bool bRegFixForOptionTab, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::StartRegFixScan(bool bRegFixForOptionTab)
{
	CRegFix objRegFix;
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objRegFix.Load(csMaxDBPath + SD_DB_REGFIX);
	REGFIX oRegFixData = {0};
	m_oDuplicateRegFixEntry.RemoveAll();
	if(objRegFix.GetFirst(oRegFixData) != NULL)
    {
        bool bFound = true;
		m_bRegFixForOptionTab = bRegFixForOptionTab;
		CString csCurrentUserPath = m_oDBPathExpander.GetCurrentUserPath();
        while(bFound && !m_bStopScanning)
        {
			LPBYTE pDataToCheck = NULL;
			DWORD dwSizeOfDataToCheck = 0;
			if(m_oDBPathExpander.RunningOnVista())
			{
				pDataToCheck = (oRegFixData.byCommonForAll ? oRegFixData.pbyFixValue : oRegFixData.pbyValueForVista);
				dwSizeOfDataToCheck = (oRegFixData.byCommonForAll ? oRegFixData.dwFixValueSize : oRegFixData.dwValueForVistaSize);
			}
			else if(m_oDBPathExpander.RunningOnXP())
			{
				pDataToCheck = (oRegFixData.byCommonForAll ? oRegFixData.pbyFixValue : oRegFixData.pbyValueForXP);
				dwSizeOfDataToCheck = (oRegFixData.byCommonForAll ? oRegFixData.dwFixValueSize : oRegFixData.dwValueForXPSize);
			}
			else if(m_oDBPathExpander.RunningOnWin7())
			{
				pDataToCheck = (oRegFixData.byCommonForAll ? oRegFixData.pbyFixValue : oRegFixData.pbyValueForWindows7);
				dwSizeOfDataToCheck = (oRegFixData.byCommonForAll ? oRegFixData.dwFixValueSize : oRegFixData.dwValueForWindows7Size);
			}
			else
			{
				pDataToCheck = oRegFixData.pbyFixValue;
				dwSizeOfDataToCheck = oRegFixData.dwFixValueSize;
			}

			REG_FIX_OPTIONS sReg_Fix_Options = {0};
			sReg_Fix_Options.FIX_TYPE	= oRegFixData.byFixType;
			sReg_Fix_Options.FIX_ACTION = oRegFixData.byFixAction;

			LPTSTR strValuePath = NULL;
			if(m_objRegistryValueType.SearchItem(oRegFixData.dwValueTypeID, &strValuePath))
			{           
				if(oRegFixData.byHiveType == 1)        
				{
					CheckRegFixValue(HKEY_LOCAL_MACHINE, CString(strValuePath) + 
									oRegFixData.szKeyPart, oRegFixData.szValuePart, 
									oRegFixData.pbyDataPart, oRegFixData.dwDataPartSize, 
									pDataToCheck, dwSizeOfDataToCheck, oRegFixData.dwSpyNameID, 
									csCurrentUserPath, sReg_Fix_Options);
				}
				else
				{
					if(oRegFixData.byHiveType == 3)
					{
						CheckRegFixValue(HKEY_LOCAL_MACHINE, CString(strValuePath) + oRegFixData.szKeyPart, 
										oRegFixData.szValuePart, oRegFixData.pbyDataPart, 
										oRegFixData.dwDataPartSize, pDataToCheck, 
										dwSizeOfDataToCheck, oRegFixData.dwSpyNameID, 
										csCurrentUserPath, sReg_Fix_Options);
					}

					LPVOID posUserName = m_objAvailableUsers.GetFirst();
					while(posUserName && !m_bStopScanning)
					{
						LPTSTR strUserSID = NULL;
						LPTSTR strUserPath = NULL;
						m_objAvailableUsers.GetKey(posUserName, strUserSID);
						m_objAvailableUsers.GetData(posUserName, strUserPath);
						if(strUserSID && strUserPath)
						{
							CString csFullPath;
							csFullPath.Format(L"%s\\%s%s", strUserSID, strValuePath, oRegFixData.szKeyPart);
							CheckRegFixValue(HKEY_USERS, csFullPath, oRegFixData.szValuePart, 
												oRegFixData.pbyDataPart, oRegFixData.dwDataPartSize, 
												pDataToCheck, dwSizeOfDataToCheck, oRegFixData.dwSpyNameID, 
												strUserPath, sReg_Fix_Options);
						}
						posUserName = m_objAvailableUsers.GetNext(posUserName);
					}
				}
			}
			bFound = objRegFix.GetNext(oRegFixData);
        }
        objRegFix.RemoveAll();
		m_oDuplicateRegFixEntry.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_REGFIX);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::CheckRegFixValue
In Parameters  : HKEY hKey, LPCTSTR wcsMainKey, LPCTSTR wcsValue, LPBYTE lpDataPart, 
					DWORD dwSizeofDataPart, LPBYTE lpFixDataPart, DWORD dwFixDataPartSize, 
					ULONG ulSpyNameID, LPCTSTR wcsProfilePath, REG_FIX_OPTIONS &sReg_Fix_Options, 
Out Parameters : void 
Description    : 
				// (m_bRegFixForOptionTab == true)	->	all entrys should be checked against fixvalue and if not same take action
				// (byFixType == 2)					->	Always Fix (check db data_part in system, if not same take action)
				// (byFixType == 3)					->	Fix if Default Value not present (check db fixvalue in system, if not same take action)
				// (byFixType == 1)					->	Check if fixvalue is present in system, if not report it to the ui (ui will show entry in list only of that spyware name was already found by any other scanner)
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::CheckRegFixValue(HKEY hKey, LPCTSTR wcsMainKey, LPCTSTR wcsValue, 
									 LPBYTE lpDataPart, DWORD dwSizeofDataPart, LPBYTE lpFixDataPart, 
									 DWORD dwFixDataPartSize, ULONG ulSpyNameID, LPCTSTR wcsProfilePath, 
									 REG_FIX_OPTIONS &sReg_Fix_Options)
{
	DWORD dwDataType = 0;
	BYTE bSystemData[MAX_PATH*4] = {0};
	DWORD dwBuffSize = MAX_PATH*4;
    if(!m_bStopScanning && QueryRegData(wcsMainKey, wcsValue, dwDataType, bSystemData, dwBuffSize, hKey))
	{
		LPBYTE lpbDBData = (m_bRegFixForOptionTab 
							? lpFixDataPart : (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_ONLY_IF_SPY_FOUND 
							? lpDataPart : (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_ALWAYS_FIX 
							? lpDataPart : (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_IF_DEFAULT_NOT_FOUND 
							? lpFixDataPart : lpFixDataPart))));

		(m_bRegFixForOptionTab 
								? dwFixDataPartSize : (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_ONLY_IF_SPY_FOUND 
								? dwSizeofDataPart : (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_ALWAYS_FIX 
								? dwSizeofDataPart : (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_IF_DEFAULT_NOT_FOUND 
								? dwFixDataPartSize : dwFixDataPartSize))));
		LPBYTE lpbDBDataToReport = NULL;
		DWORD dwSizeOfDBDataToReport = 0;
		bool bCheckResult = true;
		if((dwDataType == REG_SZ) || (dwDataType == REG_EXPAND_SZ))
		{
			_wcslwr_s((WCHAR*)bSystemData, dwBuffSize / sizeof(TCHAR));
			CString csDBData((WCHAR*)lpbDBData);
			CString csSysData((WCHAR*)bSystemData);
			csSysData.Remove('"');
			csDBData.Remove('"');
			csDBData = m_oDBPathExpander.ExpandPath(csDBData, wcsProfilePath);
			csSysData = m_oDBPathExpander.ExpandSystemPath(csSysData);
			bCheckResult = (csDBData == csSysData);

			if(sReg_Fix_Options.FIX_ACTION == FIX_ACTION_REMOVE_DATA) // this is only to show formated empty data on the UI
			{
				dwSizeOfDBDataToReport = sizeof(TCHAR);
				lpbDBDataToReport = new BYTE[dwSizeOfDBDataToReport];
				memset(lpbDBDataToReport, 0, dwSizeOfDBDataToReport);
			}
			else
			{
				if(sReg_Fix_Options.FIX_ACTION == FIX_ACTION_RESTORE)
				{
					csDBData = m_oDBPathExpander.ExpandPath((WCHAR*)lpFixDataPart, wcsProfilePath);
				}
				dwSizeOfDBDataToReport = ((csDBData.GetLength() + sizeof(TCHAR)) * sizeof(TCHAR));
				lpbDBDataToReport = new BYTE[dwSizeOfDBDataToReport];
				memset(lpbDBDataToReport, 0, dwSizeOfDBDataToReport);
				memcpy_s(lpbDBDataToReport, dwSizeOfDBDataToReport, (LPVOID)(LPCTSTR)csDBData, 
						csDBData.GetLength() * sizeof(TCHAR));
			}
		}
		else if(dwDataType == REG_DWORD)
		{
			DWORD dwSystemData = 0;
			memcpy(&dwSystemData, bSystemData, dwBuffSize);
			DWORD dwDBData = _wtoi((WCHAR*)lpbDBData);
			bCheckResult = (dwDBData == dwSystemData);

			if(sReg_Fix_Options.FIX_ACTION == FIX_ACTION_REMOVE_DATA) // this is only to show formated empty data on the UI
			{
				dwSizeOfDBDataToReport = sizeof(DWORD);
				lpbDBDataToReport = new BYTE[dwSizeOfDBDataToReport];
				memset(lpbDBDataToReport, 0, dwSizeOfDBDataToReport);
			}
			else
			{
				if(sReg_Fix_Options.FIX_ACTION == FIX_ACTION_RESTORE)
				{
					dwDBData = _wtoi((WCHAR*)lpFixDataPart);
				}

				dwSizeOfDBDataToReport = sizeof(DWORD);
				lpbDBDataToReport = new BYTE[dwSizeOfDBDataToReport];
				memset(lpbDBDataToReport, 0, dwSizeOfDBDataToReport);
				memcpy_s(lpbDBDataToReport, dwSizeOfDBDataToReport, &dwDBData, dwSizeOfDBDataToReport);
			}
		}
		else	// unhandled case
			return;

		if((m_bRegFixForOptionTab) && (!bCheckResult))
		{
			ULONG ulData = 0;
			CString csReport;
			csReport.Format(L"%s-%s", wcsMainKey, wcsValue);
			csReport.MakeLower();
			if(!m_oDuplicateRegFixEntry.SearchItem(csReport, &ulData))
			{
				m_oDuplicateRegFixEntry.AppendItem(csReport, 0);
				SendScanStatusToUI(RegFix, ulSpyNameID, hKey, wcsMainKey, wcsValue, 
									dwDataType, bSystemData, dwBuffSize, &sReg_Fix_Options, 
									lpbDBDataToReport, dwSizeOfDBDataToReport);
			}
		}
		else if((!m_bRegFixForOptionTab) && ((sReg_Fix_Options.FIX_TYPE == FIX_TYPE_ONLY_IF_SPY_FOUND) 
							|| (sReg_Fix_Options.FIX_TYPE == FIX_TYPE_ALWAYS_FIX)) && (bCheckResult))
		{
			ULONG ulData = 0;
			CString csReport;
			csReport.Format(L"%s-%s", wcsMainKey, wcsValue);
			csReport.MakeLower();
			if(!m_oDuplicateRegFixEntry.SearchItem(csReport, &ulData))
			{
				m_oDuplicateRegFixEntry.AppendItem(csReport, 0);
				SendScanStatusToUI(RegFix, ulSpyNameID, hKey, wcsMainKey, wcsValue, dwDataType, 
									bSystemData, dwBuffSize, &sReg_Fix_Options, lpbDBDataToReport, 
									dwSizeOfDBDataToReport);
			}
		}
		else if((!m_bRegFixForOptionTab) 
				&& (sReg_Fix_Options.FIX_TYPE != FIX_TYPE_ONLY_IF_SPY_FOUND) 
				&& (sReg_Fix_Options.FIX_TYPE != FIX_TYPE_ALWAYS_FIX) && (!bCheckResult))
		{
			ULONG ulData = 0;
			CString csReport;
			csReport.Format(L"%s-%s", wcsMainKey, wcsValue);
			csReport.MakeLower();
			if(!m_oDuplicateRegFixEntry.SearchItem(csReport, &ulData))
			{
				m_oDuplicateRegFixEntry.AppendItem(csReport, 0);
				SendScanStatusToUI(RegFix, ulSpyNameID, hKey, wcsMainKey, wcsValue, dwDataType, 
									bSystemData, dwBuffSize, &sReg_Fix_Options, lpbDBDataToReport, 
									dwSizeOfDBDataToReport);
			}
		}
		if(lpbDBDataToReport)
		{
			delete [] lpbDBDataToReport;
			lpbDBDataToReport = NULL;
		}
	}       
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanUsingRegValDB
In Parameters  : CUUSSU &objDBMap, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanUsingRegValDB(CUUSSU &objDBMap)
{
	LPVOID posProfType = objDBMap.GetFirst();
	while((!m_bStopScanning) && (posProfType))
	{
		ULONG lProfType = 0;
		objDBMap.GetKey(posProfType, lProfType);
		CU2OS2O oValueType(true);
		objDBMap.GetData(posProfType, oValueType);
		if(lProfType == 1)
		{
			ScanNonProfilePathValue(oValueType);
		}
		else if(lProfType == 2)
		{
			ScanProfilePathValue(oValueType);
		}
		else if(lProfType == 3)
		{
			ScanNonProfilePathValue(oValueType);
			ScanProfilePathValue(oValueType);
		}

		posProfType = objDBMap.GetNext(posProfType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanNonProfilePathValue
In Parameters  : CU2OS2O &oValueType, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanNonProfilePathValue(CU2OS2O &oValueType)
{
	LPVOID posValueType = oValueType.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		ULONG lValueTypeID = 0;
		oValueType.GetKey(posValueType, lValueTypeID);
		CS2OS2U oKeyNValue(true);
		oValueType.GetData(posValueType, oKeyNValue);

		LPTSTR strValuePath = NULL;
		if(m_objRegistryValueType.SearchItem(lValueTypeID, &strValuePath))
		{
			ScanValueByKeyDB(oKeyNValue, strValuePath, HKEY_LOCAL_MACHINE);
#ifdef WIN64
			if(strValuePath[6] != '\\')  // a slash at 6th location is only possible incase it's a System Entry
			{
				WCHAR strWow64ValuePath[MAX_PATH] = {0};
				wcscpy_s(strWow64ValuePath, MAX_PATH, L"Software\\Wow6432Node");
				wcscat_s(strWow64ValuePath, MAX_PATH, &strValuePath[8]); 
				ScanValueByKeyDB(oKeyNValue, strWow64ValuePath, HKEY_LOCAL_MACHINE);
			}
#endif
		}

		posValueType = oValueType.GetNext(posValueType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanProfilePathValue
In Parameters  : CU2OS2O &oValueType, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanProfilePathValue(CU2OS2O &oValueType)
{
	LPVOID posValueType = oValueType.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		ULONG lValueTypeID = 0;
		oValueType.GetKey(posValueType, lValueTypeID);
		CS2OS2U oKeyNValue(true);
		oValueType.GetData(posValueType, oKeyNValue);

		LPVOID posUserName = m_objAvailableUsers.GetFirst();
		while((!m_bStopScanning) && (posUserName))
		{
			LPTSTR strValuePath = NULL;
			if(m_objRegistryValueType.SearchItem(lValueTypeID, &strValuePath))
			{
				LPTSTR strUserSID = NULL;
				m_objAvailableUsers.GetKey(posUserName, strUserSID);
				ScanValueByKeyDB(oKeyNValue, strUserSID + CString(L"\\") + strValuePath, HKEY_USERS);
#ifdef WIN64
				if(strValuePath[6] != '\\')  // a slash at 6th location is only possible incase it's a System Entry
				{
					WCHAR strWow64ValuePath[MAX_PATH] = {0};
					wcscpy_s(strWow64ValuePath, MAX_PATH, L"Software\\Wow6432Node");
					wcscat_s(strWow64ValuePath, MAX_PATH, &strValuePath[8]); 
					ScanValueByKeyDB(oKeyNValue, strUserSID + CString(L"\\") + strWow64ValuePath, HKEY_USERS);
				}
#endif
			}
			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}
		posValueType = oValueType.GetNext(posValueType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::ScanValueByKeyDB
In Parameters  : CS2OS2U &oKeyNValue, const CString &csValuePath, HKEY hHiveToScan, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryBase::ScanValueByKeyDB(CS2OS2U &oKeyNValue, const CString &csValuePath, HKEY hHiveToScan)
{
	LPVOID posValueType = oKeyNValue.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		LPCTSTR lpstrKeyPart = NULL;
		oKeyNValue.GetKey(posValueType, lpstrKeyPart);
		CS2U oValueNSpyID(true);
		oKeyNValue.GetData(posValueType, oValueNSpyID);

		ScanRegistryValue(csValuePath + lpstrKeyPart, hHiveToScan, oValueNSpyID, RegValue, true);

		posValueType = oKeyNValue.GetNext(posValueType);
	}
}

/*-------------------------------------------------------------------------------------
Function		: CRegistryBase::GetFilePathFromRegData
In Parameters	: LPCTSTR szRegData, CString& csFilePath
Out Parameters	: bool
Purpose			: get file path from given reg data read from registry values
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegistryBase::GetFilePathFromRegData(LPCTSTR szRegData, CString& csFilePath)
{
	bool bFilePathFound = false;
	TCHAR szFilePath[MAX_PATH] = {0};
	LPCTSTR Ptr = NULL, StartPtr = NULL, EndPtr = NULL;

	if(Ptr = _tcsstr(szRegData, _T("rundll32.exe\"")))
	{
		Ptr += _tcslen(_T("rundll32.exe\""));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32.exe")))
	{
		Ptr += _tcslen(_T("rundll32.exe"));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32\"")))
	{
		Ptr += _tcslen(_T("rundll32\""));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32")))
	{
		Ptr += _tcslen(_T("rundll32"));
	}
	else
	{
		Ptr = szRegData;
	}

	while(true)
	{
		if(NULL == StartPtr)
		{
			if((_T(' ') != *Ptr) && (_T('"') != *Ptr))
			{
				StartPtr = Ptr;
			}
		}
		else
		{
			if((0 == *Ptr) || (_T('"') == *Ptr))
			{
				EndPtr = Ptr;
				break;
			}
		}

		if(0 == *Ptr)
		{
			break;
		}

		Ptr++;
	}

	if(!StartPtr || !EndPtr || StartPtr >= EndPtr)
	{
		return bFilePathFound;
	}

	if(EndPtr - StartPtr >= _countof(szFilePath))
	{
		return bFilePathFound;
	}

	_tcsncpy_s(szFilePath, _countof(szFilePath), StartPtr, EndPtr - StartPtr);

	if(_tcsrchr(szFilePath, _T('.')))
	{
		LPTSTR DotPtr = _tcsrchr(szFilePath, _T('.'));
		if(!_tcsnicmp(DotPtr, _T(".exe"), 4))
		{
			DotPtr [ 4 ] = 0;
		}
	}

	//if(!_tcschr(szFilePath, _T('\\')))
	//{
	//	_tsearchenv_s(szFilePath, _T("PATH"), szFilePath, _countof(szFilePath));
	//}

	csFilePath = szFilePath;
	bFilePathFound = true;
	return bFilePathFound;
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::CheckIfFilePresent
In Parameters  : LPCTSTR szData
Out Parameters : bool
Description    : if the data contains a filename return true else false
Author & Date  : Anand Srivastava & 8 March, 2010
--------------------------------------------------------------------------------------*/
bool CRegistryBase::CheckIfFilePresent(LPCTSTR szData)
{
	TCHAR szFullPath[MAX_PATH] = {0};
	CString csFullPath;

	if(_tcsstr(szData, _T(":\\")))
	{
		return true;
	}

	/*_tsearchenv_s(szData, _T("PATH"), szFullPath, _countof(szFullPath));
	if(_tcsstr(szFullPath, _T(":\\")))
	{
		return true;
	}*/

	GetFilePathFromRegData(szData, csFullPath);
	if(-1 != csFullPath.Find(_T(":\\")))
	{
		return true;
	}

	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::SearchScannedFileFolderInValueData
In Parameters  : LPCTSTR szValue, int iDataType, LPCBYTE byData, bool& bIsFileFound
Out Parameters : bool
Description    : file present of scanned list, true. no file present, true. else, false.
Author & Date  : Anand Srivastava & 8 March, 2010
--------------------------------------------------------------------------------------*/
bool CRegistryBase::SearchScannedFileFolderInValueData(LPCTSTR szValue, int iDataType, LPBYTE byData,
													   bool& bIsFileFound)
{
	DWORD dwSpyID = 0;
	LPTSTR szFilePath = NULL;
	LPVOID lpContext = NULL;
	bool bFound = false;
	CString csFilePath, csData, csValue, csData1, csValue1;

	csValue = szValue;
	if(REG_SZ == iDataType)
	{
		csData = (LPCTSTR)byData;
	}

	csData = m_oDBPathExpander.ExpandSystemPath(csData);
	csValue = m_oDBPathExpander.ExpandSystemPath(csValue);
	csData.MakeLower();
	csValue.MakeLower();

	m_objRegPathExp.DoesFileExist(csValue);
	csValue1 = m_objRegPathExp.m_csFileFound;
	m_objRegPathExp.DoesFileExist(csData);
	csData1 = m_objRegPathExp.m_csFileFound;
	csData1.MakeLower();
	csValue1.MakeLower();

	if(m_pobjFilesList)
	{
		lpContext = m_pobjFilesList->GetFirst();
		while(lpContext)
		{
			m_pobjFilesList->GetKey(lpContext, szFilePath);

			if(szFilePath)
			{
				csFilePath = szFilePath;
				csFilePath.MakeLower();

				if((csValue != BLANKSTRING) && (-1 != csValue.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}

				if((csData != BLANKSTRING) && (-1 != csData.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}

				if((csValue1 != BLANKSTRING) && (-1 != csValue1.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}

				if((csData1 != BLANKSTRING) && (-1 != csData1.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}
			}

			lpContext = m_pobjFilesList->GetNext(lpContext);
		}
	}

	if(m_pobjFoldersList)
	{
		lpContext = m_pobjFoldersList->GetFirst();
		while(lpContext && !bIsFileFound)
		{
			m_pobjFoldersList->GetKey(lpContext, szFilePath);

			if(szFilePath)
			{
				csFilePath = szFilePath;
				csFilePath.MakeLower();

				if((csValue != BLANKSTRING) && (-1 != csValue.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}

				if((csData != BLANKSTRING) && (-1 != csData.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}

				if((csValue1 != BLANKSTRING) && (-1 != csValue1.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}

				if((csData1 != BLANKSTRING) && (-1 != csData1.Find(csFilePath)))
				{
					bIsFileFound = true;
					break;
				}
			}

			lpContext = m_pobjFoldersList->GetNext(lpContext);
		}
	}

	if(!CheckIfFilePresent(csValue) && !CheckIfFilePresent(csData) &&
		!CheckIfFilePresent(csValue1) && !CheckIfFilePresent(csData1))
	{
		bFound = true;
	}

	return (bFound || bIsFileFound);
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::SearchScannedFileFolderInKey
In Parameters  : const CString& csValue, int iDataType, LPCBYTE byData, bool& bIsFileFound
Out Parameters : bool
Description    : 
Author & Date  : Anand Srivastava & 8 March, 2010
--------------------------------------------------------------------------------------*/
bool CRegistryBase::SearchScannedFileFolderInKey(HKEY hParentKey, LPCTSTR szMainKey, bool& bIsFileFound, DWORD lSpyNameID)
{
	DWORD LengthOfLongestSubKey = 0;
	DWORD LengthOfLongestValueName = 0;
	DWORD LengthOfLongestValueData = 0;
	DWORD TypeCode = 0;
	DWORD LengthOfFullKey = 0;
	DWORD LengthOfSubKey = 0;
	DWORD LengthOfValueName = 0;
	DWORD LengthOfValueData = 0;
	LPWSTR lpFullKey = NULL;
	LPWSTR lpSubKey = NULL;
	LPWSTR lpValueName = NULL;
	LPBYTE lpValueData = NULL;
	bool bFound = true;
	HKEY hSubkey = NULL;

	// scan all the keys in Image File Execution Options
	if(_tcsnicmp(szMainKey, _T("Image File Execution Options\\"), 29) == 0)
	{
		CheckImageFileExecutionOptions(hParentKey, szMainKey, lSpyNameID);
		return true;
	}

	if(RegOpenKeyEx(hParentKey, szMainKey, 0, KEY_READ, &hSubkey) != ERROR_SUCCESS)
	{
		return false;
	}

	if(RegQueryInfoKey(hSubkey, 0, 0, 0, 0, &LengthOfLongestSubKey, 0, 0, &LengthOfLongestValueName,
						&LengthOfLongestValueData, 0, 0) != ERROR_SUCCESS)
	{
		RegCloseKey ( hSubkey ) ;
		return false;
	}

	// just a precaution, as few times RegQueryInfoKey returned lesser lengths
	if(LengthOfLongestValueName < MAX_VALUE_NAME)
	{
		LengthOfLongestValueName = MAX_VALUE_NAME;
	}
	LengthOfLongestValueName += 10;
	LengthOfLongestValueData += 10;

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
		return false;
	}

	for(int iValIdx = 0; !bIsFileFound; iValIdx++)
	{
		wmemset(lpValueName, 0, LengthOfLongestValueName);
		memset(lpValueData, 0, LengthOfLongestValueData);
		LengthOfValueName = LengthOfLongestValueName;
		LengthOfValueData = LengthOfLongestValueData;

		DWORD NTr = RegEnumValue(hSubkey, iValIdx, lpValueName, &LengthOfValueName, NULL,
									&TypeCode, lpValueData, &LengthOfValueData);
		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}
		else if(m_bStopScanning)
		{
			break;
		}

		if(LengthOfValueData >= LengthOfLongestValueData)
		{
			AddLogEntry(L">> Long Data found, skipping!!");
			continue;
		}
		else
		{
			if((TypeCode == REG_SZ) || (TypeCode == REG_MULTI_SZ))
			{
				lpValueData[LengthOfValueData] = 0;
				if((TypeCode == REG_MULTI_SZ) && ((LengthOfValueData+1) < LengthOfLongestValueData))
				{
					lpValueData[LengthOfValueData+1] = 0;
				}
			}
		}

		if(!SearchScannedFileFolderInValueData(lpValueName, TypeCode, lpValueData, bIsFileFound))
		{
			bFound = false;
		}
	}

	GlobalFree(lpValueName);
	GlobalFree(lpValueData);

	if(bIsFileFound || m_bStopScanning)
	{
		RegCloseKey(hSubkey);
		return bFound;
	}

	// just a precaution, as few times RegQueryInfoKey returned lesser lengths
	if(LengthOfLongestSubKey < MAX_KEY_NAME)
	{
		LengthOfLongestSubKey = MAX_KEY_NAME;
	}

	LengthOfLongestSubKey += 10;

	lpSubKey = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestSubKey * sizeof(TCHAR));
	if(NULL == lpSubKey)
	{
		RegCloseKey(hSubkey);
		return false;
	}

	LengthOfFullKey = (DWORD)wcslen ( szMainKey ) + LengthOfLongestSubKey + 1 ;
	lpFullKey = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfFullKey * sizeof(TCHAR));
	if(NULL == lpFullKey)
	{
		GlobalFree(lpSubKey);
		RegCloseKey(hSubkey);
		return false;
	}

	for(int iCtr = 0; !bIsFileFound; iCtr++)
	{
		wmemset(lpSubKey, 0, LengthOfLongestSubKey);
		LengthOfSubKey = LengthOfLongestSubKey;

		DWORD NTr = RegEnumKey(hSubkey, iCtr, lpSubKey, LengthOfSubKey);
		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}
		else if(m_bStopScanning)
		{
			break;
		}
		else if(!lpSubKey)
		{
			continue;
		}

		if(!SearchScannedFileFolderInKey(hSubkey, lpSubKey, bIsFileFound, lSpyNameID))
		{
			bFound = false;
		}
	}

	GlobalFree(lpSubKey);
	GlobalFree(lpFullKey);
	RegCloseKey(hSubkey);
	return bFound;
}

/*--------------------------------------------------------------------------------------
Function       : CRegistryBase::CheckImageFileExecutionOptions
In Parameters  : HKEY hParentKey, LPCTSTR szKey, DWORD lSpyNameID
Out Parameters : bool
Description    : if debugger present, also report its file
Author & Date  : Anand Srivastava & 5 Jan, 2012
--------------------------------------------------------------------------------------*/
bool CRegistryBase::CheckImageFileExecutionOptions(HKEY hParentKey, LPCTSTR szKey, DWORD lSpyNameID)
{
	HKEY hSubkey = NULL;
	LONG lRetValue = 0;
	TCHAR szData[MAX_PATH] = {0}, szFullPath[MAX_PATH] = {0};
	DWORD cbData = sizeof(szData);

	if(RegOpenKeyEx(hParentKey, szKey, 0, KEY_READ, &hSubkey) != ERROR_SUCCESS)
	{
		return false;
	}

	if(RegQueryValueEx(hSubkey, _T("Debugger"), 0, 0, (LPBYTE)szData, &cbData) != ERROR_SUCCESS)
	{
		RegCloseKey(hSubkey);
		return false;
	}

	RegCloseKey(hSubkey);

	//just a caution to ensure that the string is null terminated
	szData[_countof(szData) - 1] = _T('\0');

	if(_tcsnicmp(szData, _T("ntsd "), 5) == 0 || _tcsicmp(szData, _T("ntsd")) == 0)
	{
		szFullPath[0] = _T('\0'); // set the string to blank so no reporting this file
	}
	else if(NULL == _tcschr(szData, _T('\\')))
	{
		_tsearchenv_s(szData, _T("PATH"), szFullPath, _countof(szFullPath));
	}
	else
	{
		_tcscpy_s(szFullPath, _countof(szFullPath), szData);
	}

	if(_taccess_s(szFullPath, 0))
	{
		return false;
	}

	SendScanStatusToUI(File, lSpyNameID, szFullPath, 0);
	return true;
}
