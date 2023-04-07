/*======================================================================================
   FILE				: TrojanZlobWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware TrojanZlob
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 17 April 2008
   NOTE				:
   VERSION HISTORY	: Added Code for Trojan Zlob.
					
					version: 2.5.0.32
					Resource : Shweta
					Description: Changed 
					
========================================================================================*/

#include "pch.h"
#include "TrojanZlobWorm.h"
#include "windows.h"
#include "StringFunctions.h"
#include "ExecuteProcess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and fix Trojan ZloB spyware
	Author			: Shweta
	Description		: checks  for Trojan Zlob random Entries and send them to UI
--------------------------------------------------------------------------------------*/
bool CTrojanZlobWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan ;

		if(IsStopScanningSignaled())
			return ( false ) ;

		//Read all entries from HKCU\run
		if ( !CollectRunEntries() )
			return ( false ) ; 
		
		//Enumerate process and modules
		EnumProcessAndModules ( ) ;

		if ( m_bSplSpyFound )
			CheckAppDataFile() ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CTrojanZlob::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false ) ;
}


/*-------------------------------------------------------------------------------------
	Function		: CollectRunEntries
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: collect HKCU\RUN entries
	Author			: Shweta
	Description		: make a list of all the files in Run key
--------------------------------------------------------------------------------------*/
bool CTrojanZlobWorm :: CollectRunEntries()
{
	try
	{
		m_csArrRunEntries . RemoveAll() ;
		CStringArray csRegLocations ;
		CString csSid;
		CExecuteProcess objExecuteproc;

		csSid  = objExecuteproc.GetCurrentUserSid() ;
		csRegLocations.Add ( RUN_REG_PATH ) ;
		if ( m_bScanOtherLocations )
			csRegLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;

		CStringArray csArrVal , csArrData ;
		for ( int iLocCnt = 0 ; iLocCnt < csRegLocations.GetCount() ; iLocCnt++ )
		{
			m_objReg.QueryDataValue( csSid + BACK_SLASH + csRegLocations.GetAt(iLocCnt) , csArrVal , csArrData , HKEY_USERS );

			for ( int i = 0 ; i < csArrData.GetCount() ; i++)
			{
				if ( _taccess_s ( csArrData.GetAt(i) , 0 ) != 0 )
				{
					continue;
				}
				CString csElement1 = csArrData.GetAt(i);
				csElement1 .MakeLower();
				if ( csElement1.Find ( m_objSysInfo.m_strSysDir.MakeLower() ) == -1 )
				{
					continue;
				}

				CString csElement = csArrData . GetAt(i) ;
				m_csArrRunEntries . Add ( csArrVal.GetAt(i) + L"^" +  csElement.MakeLower() );
			}
		}
		return ( true ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CTrojanZlobWorm::CollectRunEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSizeOfImage
	In Parameters	: const char * , DWORD& 
	Out Parameters	: bool
	Purpose			: get the image size of the given file
	Author			: Shweta
	Description		: read the PE structure of the file and determine the image size
--------------------------------------------------------------------------------------*/
bool CTrojanZlobWorm :: GetSizeOfImage ( LPCTSTR szImageFilename , DWORD& dwSizeOfImage )
{
	try
	{
		DWORD dwBytesRead = 0 ;
		HANDLE hFile = NULL ;
		IMAGE_NT_HEADERS NTFileHeader = { 0 } ;
		IMAGE_DOS_HEADER DosHeader = { 0 } ;

		hFile = CreateFile ( szImageFilename , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
		if ( INVALID_HANDLE_VALUE == hFile )
		{
			return ( false ) ;
		}
		if (FALSE == ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &dwBytesRead , 0 ) )
		{
			CloseHandle ( hFile );
			return ( false ) ;
		}
		
		SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
		
		if (FALSE == ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
		{
			CloseHandle ( hFile ) ;
			return ( false ) ;
		}
		
		CloseHandle ( hFile ) ;
		dwSizeOfImage = NTFileHeader . OptionalHeader . SizeOfImage ;
		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyCrushWorm::GetSizeOfImage, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckMemDetails
	In Parameters	: const CString& , HANDLE , HMODULE 
	Out Parameters	: bool
	Purpose			: scan the process memory
	Author			: Shweta
	Description		: scan the module's memory from the process for some keywords
--------------------------------------------------------------------------------------*/
bool CTrojanZlobWorm :: CheckMemDetails ( const CString& csFilename , HANDLE hProcess , HMODULE hModule , int iRunCnt)
{
	try
	{
		DWORD dwSizeOfImage = 0 ;
		SIZE_T dwBytesRead = 0 ;
		unsigned char * Buffer = NULL ;
		char * szSearchString1 = "antispyware-reviews.biz" ;

		if ( !GetSizeOfImage ( csFilename , dwSizeOfImage ) )
			return ( false ) ;

		Buffer = new unsigned char [ dwSizeOfImage ] ;
		if ( !Buffer )
			return ( false ) ;

		memset ( Buffer , 0 , dwSizeOfImage ) ;
		if ( !ReadProcessMemory ( hProcess , hModule , Buffer , dwSizeOfImage , &dwBytesRead ) )
		{
			delete []Buffer ;
			return ( false ) ;
		}

		if ( StrNIStr ( Buffer , dwBytesRead , (UCHAR*) szSearchString1 , strlen ( szSearchString1 ) ) )
		{
			CString csData , csValue;
			csData = m_csArrRunEntries.GetAt ( iRunCnt );
			csValue = csData.Left ( csData.Find ( L"^" , 0 ));
			csData = csData.Right(csData.GetLength() - csData.Find(L"^",0) -1 ) ;

			SendScanStatusToUI ( Special_File , m_ulSpyName , csFilename) ;
			SendScanStatusToUI ( Special_Process , m_ulSpyName , csFilename   ) ;
            SendScanStatusToUI (  Special_RegVal , m_ulSpyName , HKEY_CURRENT_USER ,  CString(RUN_REG_PATH) , csValue, REG_SZ, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;
			m_bSplSpyFound = true;
		}

		delete []Buffer ;
		if ( m_bSplSpyFound ) 
			return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyCrushWorm::CheckMemDetails, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}



/*-------------------------------------------------------------------------------------
	Function		: CheckAppDataFile
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan the process memory
	Author			: Shweta
	Description		: scan the module's memory from the process for some keywords
--------------------------------------------------------------------------------------*/
void CTrojanZlobWorm::CheckAppDataFile()
{
	
	TCHAR szPath [ MAX_PATH ] = { 0 } ;
	// get user application data path
	SHGetFolderPath ( 0, CSIDL_COMMON_APPDATA  ,0 , 0, szPath);

	//Enumerate HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\explorer\run entries
    vector<REG_VALUE_DATA> vecRegValues;
	m_objReg.EnumValues(POLICIES_RUN_PATH, vecRegValues, HKEY_LOCAL_MACHINE);

    for ( size_t i = 0 ; i < vecRegValues.size() ; i++)
	{
        CString csData;
        csData.Format(_T("%s") , (TCHAR*)vecRegValues[i].bData);
		if ( _taccess_s ( csData , 0 ) != 0 )
			continue;

		if ( csData.Find ( szPath) == -1 )
			continue;
		if ( !m_objEnumProc.IsProcessRunning ( csData ,false ) )
			continue;

		SendScanStatusToUI ( Special_File, m_ulSpyName , csData);
		SendScanStatusToUI ( Special_Process , m_ulSpyName , csData);
		SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_LOCAL_MACHINE , + CString(POLICIES_RUN_PATH) 
            , vecRegValues[i].strValue,vecRegValues[i].Type_Of_Data,vecRegValues[i].bData,vecRegValues[i].iSizeOfData);
	}

	return ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumProcessAndModules
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan the process memory
	Author			: Anand
	Description		: scan the module's memory from the process for some keywords
--------------------------------------------------------------------------------------*/
bool CTrojanZlobWorm::EnumProcessAndModules()
{
	try
	{
		HMODULE hPSAPI = LoadLibrary ( CSystemInfo::m_strSysDir + L"\\PSAPI.DLL" ) ;
		if ( NULL == hPSAPI )
			return ( false ) ;

		m_lpfnEnumProcesses = ( LPFN_EnumProcesses ) GetProcAddress ( hPSAPI , "EnumProcesses" ) ;
		m_lpfnEnumProcessModules = ( LPFN_EnumProcessModules ) GetProcAddress ( hPSAPI , "EnumProcessModules" ) ;
		m_lpfnGetModuleFileNameEx = ( LPFN_GetModuleFileNameEx ) GetProcAddress ( hPSAPI , "GetModuleFileNameExW" ) ;
		if ( !m_lpfnEnumProcesses || !m_lpfnEnumProcessModules || !m_lpfnGetModuleFileNameEx )
		{
			m_lpfnEnumProcesses = NULL ;
			m_lpfnEnumProcessModules = NULL ;
			m_lpfnGetModuleFileNameEx = NULL;
			FreeLibrary ( hPSAPI ) ;
			return ( false ) ;
		}

		DWORD aProcesses[1024] = { 0 } , cbNeeded, cProcesses , cbNeed;
		HANDLE hProcess ;
		HMODULE hMods[1024] = { 0 } ;
		TCHAR szModName [ MAX_PATH ] = { 0 } ;
		TCHAR szProcessName [ MAX_PATH ] = { 0 } ;
		CString csTemp;
		bool bFoundFlag ;

		if ( !m_lpfnEnumProcesses ( aProcesses, sizeof(aProcesses),&cbNeeded ))
		{
			m_lpfnEnumProcesses = NULL ;
			m_lpfnEnumProcessModules = NULL ;
			m_lpfnGetModuleFileNameEx = NULL;
			FreeLibrary ( hPSAPI ) ;
			return false;
		}

		cProcesses = cbNeeded / sizeof(DWORD);
		for ( int  i = 0 ; i < static_cast<int>(cProcesses) ; i++ )
		{
			hProcess = OpenProcess ( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE , aProcesses [ i ] ) ;
			if ( NULL == hProcess )
				continue ;
			if ( m_lpfnGetModuleFileNameEx( hProcess , NULL , szProcessName , _countof ( szProcessName ) ) )
			{
				for ( int iRunCnt = 0; iRunCnt < m_csArrRunEntries.GetCount() ;iRunCnt++)
				{
					csTemp = m_csArrRunEntries.GetAt(iRunCnt);
					csTemp = csTemp.Right(csTemp.GetLength() - csTemp.Find(L'^',0) - 1 );
					csTemp.MakeLower();
	
					if ( CString (szProcessName).MakeLower() == csTemp )
					{
						cbNeed = 0 ;
						memset ( hMods , 0 , sizeof ( hMods ) ) ;
						if ( !m_lpfnEnumProcessModules ( hProcess , hMods , sizeof(hMods) , &cbNeed ) )
						{
							CloseHandle ( hProcess ) ;
							continue ;
						}

						for ( int j = 0 ; j < static_cast<int>( cbNeed / sizeof(HMODULE) ) ; j++ )
						{
							memset ( szModName , 0 , sizeof ( szModName ) ) ;
							if ( m_lpfnGetModuleFileNameEx ( hProcess , hMods [ j ] , szModName , _countof ( szModName ) ) )
							{
								if ( _tcsicmp ( szModName , csTemp ) == 0)
								{
									if ( CheckMemDetails ( CString ( szModName ) , hProcess , hMods [ j ] , iRunCnt) )
										bFoundFlag = true;
								}
							}
						}
					}
				}
			}
			CloseHandle ( hProcess ) ;
		}
		FreeLibrary ( hPSAPI ) ;
		if ( bFoundFlag )
			return ( true ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CTrojanZlobWorm::EnumProcessAndModules, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);

	}
	return ( false ) ;
}
