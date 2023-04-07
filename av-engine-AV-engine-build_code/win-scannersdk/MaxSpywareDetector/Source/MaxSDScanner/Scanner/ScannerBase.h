/*======================================================================================
FILE             : ScannerBase.h
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
				  
CREATION DATE    : 8/1/2009 7:50:33 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "DBPathExpander.h"
#include "CPUInfo.h"
#include "EnumProcess.h"
#include "FileOperations.h"
#include "Registry.h"
#include "MaxConstant.h"
#include "SDSAConstants.h"
#include "U2S.h"
#include "S2U.h"
#include "S2S.h"
#include <vector>
#include "RegistryHelper.h"
#include "RegPathExpander.h"
#include "MaxScanner.h"

using namespace std;

class CScannerBase
{
public:
	CScannerBase();
	virtual ~CScannerBase(void);

	void StopScanning()
	{
		m_bStopScanning = true;
	}

	void SetReporter(SENDMESSAGETOUIMS lpSendMessaegToUI, CMaxScanner *pMaxScanner)
	{
		m_lpSendMessaegToUI = lpSendMessaegToUI;
		m_objRegHelper.SetReporter(lpSendMessaegToUI);
		m_pMaxScanner = pMaxScanner;
	}

	SENDMESSAGETOUIMS GetReporter()
	{
		return m_lpSendMessaegToUI;
	}

protected:
	bool m_bDeepScan;
	bool m_bStopScanning;
	bool m_bStatusBar;
	bool m_bRegFixForOptionTab;
	bool m_bUSBScan;
	bool m_bScanReferences;
	CS2U* m_pobjFilesList;
	CS2U* m_pobjFoldersList;

	CMaxScanner				*m_pMaxScanner;
	static CRegistry		m_oRegistry;
	static CDBPathExpander	m_oDBPathExpander;
	static CCPUInfo			m_oCPUInfo;
	static CEnumProcess		m_oEnumProcess;
	static CU2S				m_objFileValueType;
	static CU2S				m_objRegistryValueType;
	static CS2S				m_objAvailableUsers;
	static CRegistryHelper	m_objRegHelper;
	static CRegPathExpander	m_objRegPathExp;

	bool EnumSubKeys(CString csMainKey,	CS2U &objSubKeyArr,	HKEY hHiveKey);
	void EnumValues(CString csMainKey, vector<REG_VALUE_DATA> &vecRegValues, HKEY hHiveKey);
	bool QueryRegData(LPCWSTR strKeyPath, LPCWSTR strValueName, DWORD &dwDataType, LPBYTE lpbData, DWORD &dwBuffSize, HKEY HiveRoot);

	void SendScanStatusToUI(PMAX_SCANNER_INFO pScannerInfo);
	void SendScanStatusToUI(SD_Message_Info eTypeOfScanner);
	void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const TCHAR *strValue, const TCHAR *strSignature);
	void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData);

	// Used for creating dummy entries!
	//void CreateDirectory(CString csFolderName);
	void CreateFileEntry(CString csEntry, int iTypeOfEntry);

	void CreateProfileEntry(int iValueType, CString csEntry, int iTypeOfEntry);
	void CreateNonProfileEntry(int iValueType, CString csEntry, int iTypeOfEntry);

	ULONG GetOtherValueTypeID(ULONG lValueTypeID);

	void PrepareMD5ForLog(WCHAR *wcsMD5, int iBuffSize, LPBYTE MD5Signature, LPDWORD pdwIndex);
	void PreparePESigForLog(WCHAR *wcsPE, int iBuffSize, LPBYTE PrimSign, LPBYTE SecSign, LPDWORD pdwIndex);

	void SetFullLiveUpdateReg(LPCTSTR szFile);

private:
	void LoadFileValuePath();
	void LoadRegistryValuePath();
	void CallToStatusBarFucn ();

	SENDMESSAGETOUIMS m_lpSendMessaegToUI;
};
