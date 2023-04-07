/*=====================================================================================
   FILE				: ReferencesScanner.h
   ABSTRACT			: class declaration for scanning for references
   DOCUMENTS		: Virus Scanner Design Document.doc
   AUTHOR			: 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created in 2008 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   VERSION HISTORY	:
=====================================================================================*/
#pragma once
#include "MaxConstant.h"
#include "Registry.h"
#include "Constants.h"
#include "SDSystemInfo.h"
#include "DBPathExpander.h"
#include "RegistryHelper.h"
#include "RegPathExpander.h"
#include "S2U.h"

#define REF_ID_RUN			0x00000001
#define REF_ID_JOB			0x00000002
#define REF_ID_INI			0x00000004
#define REF_ID_SERVICES		0x00000008
#define REF_ID_POL_EXP_RUN	0x00000010
#define REF_ID_IMG_FILE		0x00000020
#define REF_ID_USER_INIT	0x00000040
#define REF_ID_SHELL		0x00000080
#define REF_ID_BHO			0x00000100
#define REF_ID_SSODL		0x00000200
#define REF_ID_SEH			0x00000400
#define REF_ID_STS			0x00000800
#define REF_ID_APP_INIT		0x00001000
#define REF_ID_NOTIFY		0x00002000
#define REF_ID_TOOLBAR		0x00004000
#define REF_ID_MENU_EXT		0x00008000
#define REF_ID_ACTIVEX		0x00010000
#define REF_ID_SHRD_DLLS	0x00020000
#define REF_ID_UNINSTALL	0x00040000
#define REF_ID_INST_COMP	0x00080000
#define REF_ID_HIDN_FLDR	0x00100000
#define REF_ID_EXE_ASSOC	0x00200000
#define REF_ID_LOAD_RUN		0x00400000
#define REF_ID_TASKMAN		0x00800000
#define REF_ID_ALL			0xFFFFFFFF

#define CHECK_OPTION(x,y)	((((x)&(y)) == (y)) || ((x) == (REF_ID_ALL)))

typedef bool (*LPFN_FileFound)(LPCTSTR szFilePath, LPVOID lpThis, bool& bStopScan,INT_PTR iTotalEntries,INT_PTR iCounter);

int	InitScannerThread(LPVOID pThisptr);

class CReferencesScanner
{
public:

	CReferencesScanner() ;
	~CReferencesScanner() ;

	void DumpLog();

	bool OldCheckAndReportReferences(LPCTSTR szInfectedFileName, ULONG ulVirusName,
									DWORD dwReferenceID, SENDMESSAGETOUIMS lpSendMessageToUI);
	bool CheckAndReportReferences(LPCTSTR szInfectedFileName, ULONG ulVirusName,
									DWORD dwReferenceID, SENDMESSAGETOUIMS lpSendMessageToUI);
	void SetCallbackForFiles(LPFN_FileFound lpfnFileFound, LPVOID lpThis);

	bool InitReferenceScanner();

private:

	bool					m_bStopScan;
	bool					m_bInitScanners;
	bool					m_bStartReferencesCheck ;
	SENDMESSAGETOUIMS		m_lpRefSendMessageToUI ;
	CRegistry				m_objReg ; 
	CRegistryHelper			m_objRegHlp;
	CDBPathExpander			m_objDBPathExpander ;
	CRegPathExpander		m_objRegPathExpander ;
	CString					m_objFileUnderCheck;
	LPFN_FileFound			m_lpfnFileFound;
	LPVOID					m_lpThis;

	CStringArray			m_csArrUsersList;
	CStringArray			m_csArrJobNames;
	CStringArray			m_csArrJobFileNames;
	CStringArray			m_csArrServicesKeys;
	CStringArray			m_csArrServicesData;
	CStringArray			m_csArrRunKeysList;
	CStringArray			m_csArrPolExpRunList;
	CStringArray			m_csArrImgFileExecOptList;
	CStringArray			m_csArrBHOList;
	CStringArray			m_csArrSSODLList;
	CStringArray			m_csArrSEHList;
	CStringArray			m_csArrSTSList;
	CStringArray			m_csArrNotifyList;
	CStringArray			m_csArrMenuExtList, m_csArrMenuExtListOfUsers;
	CStringArray			m_csArrToolbarList;
	CStringArray			m_csArrActiveXList;
	CStringArray			m_csArrShrdDllsList;
	CStringArray			m_csArrServiceDLLKey;
	CStringArray			m_csArrServiceDLLData;

	bool InitAllUsersList();
	bool InitJobCheck();
	bool InitServicesCheck();
	bool InitKeysList();
	bool InitImgFileExecOpt();
	bool InitMenuExtensionList();
	bool InitScanners();
	bool DeInitScanners();

	

	bool CheckFileNameInIni(LPCTSTR szInfectedFileName ,ULONG ulVirusName, LPCTSTR szINFFileName);
	bool CheckFileNameInRegData(LPCTSTR szInfectedFileName, ULONG ulVirusName, LPCTSTR szRegKey,
								HKEY hHive, bool bCheckInValueAlso = false);
	bool CheckFileNameInRegData(HKEY hHive, LPCTSTR szRegKey, LPCTSTR szRegValue, LPCTSTR szDefaultRegData,
								LPCTSTR szFilePath, ULONG ulSpyID);
	bool CheckFileNameInCLSIDByRegKey(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID);
	bool CheckFileNameInCLSIDByRegValue(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID);
	bool CheckFileNameInCLSIDByRegData(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID,
										bool bReportFullKey = false);
	bool CheckFileNameInCLSIDBySubKey(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID);

	bool CheckFileNameInJob(LPCTSTR szInfectedFileName, ULONG ulVirusName);
	bool ReportCLSID(SENDMESSAGETOUI lpfnSendMessageToUI, HKEY hHive, LPCTSTR szKey, LPCTSTR szCLSID,
						DWORD dwSpyID);
	bool CheckFileNameInSubKey(LPCTSTR szFilePath, ULONG ulSpyID, LPCTSTR szRegKey, HKEY hHive,
								bool bReportFullKey = false);
	bool CheckForServices(LPCTSTR szInfectedFileName, ULONG ulVirusName);
	bool CheckFileForHiddenFolder(LPCTSTR szFilePath);

	bool RefSendMessageToUI(SD_Message_Info WormType, const ULONG ulVirusName, const CString& csFileName);
	bool RefSendMessageToUI(SD_Message_Info WormType, const ULONG ulSpyName, HKEY Hive_Type,
							const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, 
							LPBYTE lpbData, int iSizeOfData);
	bool RefSendMessageToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type,
							const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData,
							int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
							int iSizeOfReplaceData);




private:

	DWORD m_dwNoOfFilesSearched, m_dwRefInitTime, m_dwRefScanTime;
	bool m_bDummyCallDone;
	CS2U m_oFileReferenceList;
	void AddFileInList(CString csFileName);
};
