/*======================================================================================
   FILE				: Sdra64.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware sdra64 rootkit
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Yuvraj 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 13-3-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "Sdra64.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: bool
	Purpose			: 
	Author			: Yuvraj
	Description		: main entry point of this class for spyware scanning
--------------------------------------------------------------------------------------*/
bool CSdra64::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
 	try
	{
		CString csData;

		if(IsStopScanningSignaled())
		{
			return m_bSplSpyFound;
		}

		m_objReg.Get(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
			_T("Userinit"), csData, HKEY_LOCAL_MACHINE);

		csData.MakeLower();
		
		int iIndex = csData.Find(_T(":\\windows\\system32\\sdra64.exe"));
		
		if(iIndex == -1) //sdra not found
		{
			return m_bSplSpyFound;
		}
		else 
		{
			m_bSplSpyFound = true;
			AddEntryInMaxManagerIni(bToDelete);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSdra64::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry( csErr, 0, 0 );
	}
	
	return( false );
}

/*-------------------------------------------------------------------------------------
	Function		: AddEntryInMaxManagerIni
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Add entries in AuManager.ini
	Author			: Yuvraj
	Description		: To add sdra64 rootkit related entries in AuManager.ini
--------------------------------------------------------------------------------------*/
bool CSdra64::AddEntryInMaxManagerIni(bool bToDelete)
{
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	CStringArray csFileArr;
	INT_PTR i = 0, iTotal = 0;
	CString csDrive = strINIPath.Left(3);
	CString csTemp, csFile;

	if(IsStopScanningSignaled())
	{
		return m_bSplSpyFound;
	}

	csFileArr.Add(csDrive + _T("windows\\system32\\sdra64.exe"));
	csFileArr.Add(csDrive + _T("windows\\system32\\lowsec\\local.ds"));
	csFileArr.Add(csDrive + _T("windows\\system32\\lowsec\\user.ds"));
	csFileArr.Add(csDrive + _T("windows\\system32\\lowsec\\user.ds.lll"));

	if(bToDelete)
	{
		if(!::PathFileExists(strINIPath))
		{
			CreateWormstoDeleteINI(strINIPath);
		}
		
		for(i = 0, iTotal = csFileArr.GetCount(); i < iTotal; i++)
		{		
			csTemp.Format(_T("%d"), i + 500);
			csFile = _T("858481^") + csFileArr.ElementAt(i);

			WritePrivateProfileString(_T("File_Delete"), csTemp, csFile, strINIPath);		
		}
	}
	else
	{
		for(i = 0, iTotal = csFileArr.GetCount(); i < iTotal; i++)
		{
			if(!_taccess(csFileArr[i],0))
			{
				SendScanStatusToUI(Special_File_Report, m_ulSpyName, csFileArr[i]);
			}
		}

	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CreateWormstoDeleteINI
	In Parameters	: CString
	Out Parameters	: -
	Purpose			: Create AuManager.ini 
	Author			: Yuvraj
	Description		: Create AuManager.ini as unicode file
--------------------------------------------------------------------------------------*/
void CSdra64::CreateWormstoDeleteINI(const CString& strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
									FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
	}
}
