/*======================================================================================
   FILE				: InitDllWormList.cpp 
   ABSTRACT			: Adds scanned AppInit_Dlls registry entries.
   DOCUMENTS		: Refer the document Folder (SpyEliminator-LLD.Doc)
   AUTHOR			: Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: 
				  (C) Aura
  				  Created as an unpublished copyright work.  All rights reserved.
 				  This document and the information it contains is confidential and
  				  proprietary to Aura.  Hence, it may not be 
  				  used, copied, reproduced, transmitted, or stored in any form or by any 
  				  means, electronic, recording, photocopying, mechanical or otherwise, 
  				  without the prior written permission of Aura
   CREATION DATE	: 28/10/2006
   NOTES			:
    VERSION HISTORY :
					Version: 19.0.0.062
					Resource: Anand Srivastava
					Description: Checked for excluded spyware
					Version:19.0.0.064
					Resource:dipali
					Description: Exclude spyware by entry
======================================================================================*/

#include "pch.h"
#include "GenericAppInitDllScanner.h"
#include "DBPathExpander.h" 
#include "S2U.h"


/*-------------------------------------------------------------------------------------
	Function		: CheckVersionTab
	In Parameters	: CString csFilePath : file Path
	Out Parameters	: bool : true/false
	Purpose			: Check file has version tab or not
	Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CGenericAppInitDllScanner::CheckVersionTab(CString csFilePath)
{
	CString csFullFilename = csFilePath ;
	CFileFind objFind;
	CDBPathExpander objPathExpander ;
	CFileVersionInfo objVersionInfo;

	objPathExpander.ExpandSystemPath( csFullFilename ) ;

	if(!objFind.FindFile(csFullFilename))
		return false;
	if ( !objVersionInfo.DoTheVersionJob( csFullFilename, false))
	{
		//not having version tab
		//check in whitelist
		//bool bRet = IsLegitimate(csFullFilename) ? false : true ;
		return false;
	}
	return true;
}

bool CGenericAppInitDllScanner::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	CRegistry oReg;
	CString csMaxDBPath;
	oReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	CS2U objAppInitDBMap(false);
	objAppInitDBMap.Load(csMaxDBPath + SD_DB_WHITE_APPINIT);
	if(objAppInitDBMap.GetFirst() != NULL)
	{
		if(IsStopScanningSignaled())
			return false;

		ScanAppInitDataPart(objAppInitDBMap,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
#ifdef WIN64
		ScanAppInitDataPart(objAppInitDBMap, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
#endif
		objAppInitDBMap.RemoveAll();
	}
	else
	{
		m_objReg.Set(CSystemInfo::m_csProductName , _T("AutoDatabasePatch") , 1 , HKEY_LOCAL_MACHINE);
	}
	return ( m_bSplSpyFound );
}
void CGenericAppInitDllScanner::ScanAppInitDataPart(CS2U &objDBMap,LPCWSTR lstrRegistryPath)
{
	DWORD dwDataType = 0;
	BYTE bSystemData[MAX_PATH*4] = {0};
	DWORD dwBuffSize = MAX_PATH*4;
	CDBPathExpander objPathExpander ;
	CString csTempData;
	bool bFound;

	if(IsStopScanningSignaled())
		return ;

	if(QueryRegData(lstrRegistryPath, L"AppInit_DLLs", dwDataType, bSystemData, dwBuffSize, HKEY_LOCAL_MACHINE))
	{
		if((dwBuffSize > 2) && (dwDataType == REG_SZ))
		{
				CString csSysValue((LPCTSTR)bSystemData);
				CString csData((LPCTSTR)bSystemData);
			
				int curPos= 0;
				CString csSeparator;
				if(csData.Find(_T("\"")) != -1)
				{
					csSeparator = "\"";
				}
				else
					csSeparator = " ,";
                
				CString csToken = csData.Tokenize(csSeparator, curPos);
				CString csExpandPath;
			while(csToken != "")
			{
				if(IsStopScanningSignaled())
					break ;

				bFound = false;
				csExpandPath = csToken;
				csTempData = csToken;
																	
				if (csExpandPath = objPathExpander.ExpandSystemPath(csExpandPath))
					csSysValue = csExpandPath ;
			
				LPVOID lpVoid = objDBMap.GetFirst();
				while(lpVoid)
				{
					if(IsStopScanningSignaled())
						break ;

					LPTSTR lpDBValue = NULL;
					objDBMap.GetKey(lpVoid, lpDBValue);
					CString csFullPath = m_oDBPathExpander.ExpandPath(lpDBValue, L"");
					if(csSysValue.Find(csFullPath) != -1)
					{
						bFound = true;
						break;
					}
					lpVoid = objDBMap.GetNext(lpVoid);
				}

				if(!bFound )
				{
					if ( CheckVersionTab (csSysValue ))
					{
						SendScanStatusToUI (Special_File,12039,csSysValue);
						if (csSeparator == _T("\""))
							csTempData = _T("\"") + csTempData + _T("\"") ;
						SendScanStatusToUI(AppInit, 12039, HKEY_LOCAL_MACHINE, lstrRegistryPath, L"AppInit_DLLs", dwDataType, bSystemData, dwBuffSize, 0, (LPBYTE)(LPCTSTR)csTempData, (csTempData.GetLength()*sizeof(TCHAR))+sizeof(TCHAR));
					}
				}
					csToken = csData.Tokenize(csSeparator, curPos);
			}
		}
	}
}