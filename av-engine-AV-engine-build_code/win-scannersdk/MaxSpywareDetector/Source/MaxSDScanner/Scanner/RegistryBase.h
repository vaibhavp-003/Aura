/*======================================================================================
FILE             : RegistryBase.h
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
				  
CREATION DATE    : 8/1/2009 7:46:48 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "ScannerBase.h"
#include "U2OU2O.h"
#include "S2U.h"
#include "UUSSU.h"

class CRegistryBase : public CScannerBase
{
public:
	CRegistryBase(void);
	virtual ~CRegistryBase(void);

protected:
	void StartAppInitScan();
	void StartBHOScan();
	void StartActiveXScan();
	void StartMenuExtScan();
	void StartRunScan();
	void StartTooBarScan();
	void StartRegKeyScan();
	void StartRegValScan();
    void StartSSODLScan();
    void StartServicesScan();
    void StartSharedTaskScan();
	void StartNotifyScan();
	void StartSharedDllScan();
	void StartShellExecuteHooksScan();
	void StartRegFixScan(bool bRegFixForOptionTab);

private:
	CS2U m_oDuplicateRegFixEntry;
	void ScanUsingRegKeyDB(CU2OU2O &objDBMap);
	void ScanProfilePath(CU2OS2U &oValueType);
	void ScanNonProfilePath(CU2OS2U &oValueType);

	void ScanUsingRegValDB(CUUSSU &objDBMap);
	void ScanProfilePathValue(CU2OS2O &oValueType);
	void ScanNonProfilePathValue(CU2OS2O &oValueType);
	void ScanValueByKeyDB(CS2OS2U &oKeyNValue, const CString &csValuePath, HKEY hHiveToScan);

	void ScanRegistryEntry(CS2U &oValueNSpyID, const CString &csValuePath, HKEY hHiveToScan, SD_Message_Info eTypeOfScanner);
	void ScanRegistryValue(LPCWSTR lstrRegPath, HKEY hHiveToScan, CS2U &objDBMap, SD_Message_Info eTypeOfScanner, bool bExpandPath);
	void ScanRegistryValueNData(LPCWSTR lstrRegPath, HKEY hHiveToScan, CS2U &objDBMap, SD_Message_Info eTypeOfScanner, bool bExpandPath);

	void ScanUsingDBByEnrtyNSpyID(CS2U &objDBMap, LPCWSTR lstrRegistryPath, SD_Message_Info eTypeOfScanner);
	void ScanProfilePathUsingDBByEnrtyNSpyID(CS2U &objDBMap, LPCWSTR lstrRegistryPath, SD_Message_Info eTypeOfScanner, bool bExpandPath);
	void ScanProfilePathUsingDBByEnrtyNSpyIDArray(CS2U &objDBMap, CStringArray &arrRegPath, SD_Message_Info eTypeOfScanner, bool bExpandPath);

	void ScanAppInitDataPart(CS2U &objDBMap, LPCWSTR lstrRegistryPath);
	void CheckRegFixValue(HKEY hKey, LPCTSTR wcsMainKey, LPCTSTR wcsValue, LPBYTE lpDataPart, DWORD dwSizeofDataPart, LPBYTE lpFixDataPart, DWORD dwFixDataPartSize, ULONG ulSpyNameID, LPCTSTR wcsProfilePath, REG_FIX_OPTIONS &sReg_Fix_Options);

	bool CheckIfFilePresent(LPCTSTR szData);
	bool GetFilePathFromRegData(LPCTSTR szRegData, CString& csFilePath);
	bool SearchScannedFileFolderInKey(HKEY hParentKey, LPCTSTR szMainKey, bool& bIsFileFound, DWORD lSpyNameID);
	bool SearchScannedFileFolderInValueData(LPCTSTR szValue, int iDataType, LPBYTE byData, bool& bIsFileFound);
	bool CheckImageFileExecutionOptions(HKEY hParentKey, LPCTSTR szKey, DWORD lSpyNameID);
};
