/*======================================================================================
   FILE				: FakeSecurityAlert.cpp
   ABSTRACT			: This class is used for scanning Fake Security Alerts
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Shweta Mulay
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/08/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.49
					Resource : Shweta
					Description: Added code to handle fakeSecurityAlert
========================================================================================*/

#include "pch.h"
#include "FakeSecurityAlert.h"
#include "StringFunctions.h"
#include "ExecuteProcess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: FA_ProcessModuleHandler
	In Parameters	: DWORD , HANDLE , HMODULE , LPCTSTR , LPVOID , bool
	Out Parameters	: bool
	Purpose			: callback function whichi is called for every module of the given ID
	Author			: Shweta
	Description		: checks if the module is in the list of files we are currently searching
--------------------------------------------------------------------------------------*/
BOOL CALLBACK FA_ProcessMdleHandler ( DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CFakeSecurityAlertWorm * pFakeAlertWorm = (CFakeSecurityAlertWorm*) pThis ;

		bStopEnum = pFakeAlertWorm -> GetStopStatus() ;
		pFakeAlertWorm -> CheckMemDetails ( szModulePath , hProcess , hModule ) ;

		return ( TRUE ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in SpyCrushWorm, SC_ProcessModuleHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: FA_ProcessHandler
	In Parameters	: LPCTSTR , LPCTSTR , DWORD , HANDLE, LPVOID , bool 
	Out Parameters	: bool
	Purpose			: callback function whichi is called for every process
	Author			: Shweta
	Description		: checks if the process is explorer.exe and enumerates its modules
--------------------------------------------------------------------------------------*/
BOOL CALLBACK FA_ProcessHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CFakeSecurityAlertWorm * pFakeAlertWorm = (CFakeSecurityAlertWorm*) pThis ;
		CString csFileNm;

		bStopEnum = pFakeAlertWorm -> GetStopStatus() ;
		for ( int i = 0 ;i < pFakeAlertWorm->m_csArrRunEntries.GetCount() ; i++ )
		{
			
			csFileNm = pFakeAlertWorm->m_csArrRunEntries.GetAt(i);
			csFileNm = csFileNm.Right ( csFileNm.GetLength() - csFileNm.ReverseFind('\\') -1) ;
			
			if ( CString ( szExeName ) . MakeLower() == csFileNm )
			{
				pFakeAlertWorm -> m_objEnumProc . EnumProcessModuleList ( dwProcessID , szExePath, (PROCESSMODULEHANDLER)FA_ProcessMdleHandler  , pThis , true ) ;
			}
		}

		return ( TRUE ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in FakeSecurityAlertWorm, SC_ProcessHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForXPCSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and report Adware.Fake security Alert
	Author			: Shweta
	Description		: This function Get the run entries and call the Enumerate running 
					  process 
--------------------------------------------------------------------------------------*/
bool CFakeSecurityAlertWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		if ( !CollectRunEntries() )
			return ( false ) ;

		m_objEnumProc . EnumRunningProcesses ( (PROCESSHANDLER) FA_ProcessHandler , (LPVOID)this ) ;
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CFakeSecurityAlertWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}//End of function to check for MSDirect



/*-------------------------------------------------------------------------------------
	Function		: GetSizeOfImage
	In Parameters	: const char * , DWORD& 
	Out Parameters	: bool
	Purpose			: get the image size of the given file
	Author			: Shweta
	Description		: read the PE structure of the file and determine the image size
--------------------------------------------------------------------------------------*/
bool CFakeSecurityAlertWorm :: GetSizeOfImage ( LPCTSTR szImageFilename , DWORD& dwSizeOfImage )
{
	try
	{
		DWORD dwBytesRead = 0 ;
		HANDLE hFile = NULL ;
		IMAGE_NT_HEADERS NTFileHeader = { 0 } ;
		IMAGE_DOS_HEADER DosHeader = { 0 } ;

		hFile = CreateFile ( szImageFilename , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
		if ( INVALID_HANDLE_VALUE == hFile )
			return ( false ) ;

		if ( FALSE == ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &dwBytesRead , 0 ) )
		{
			CloseHandle ( hFile ) ;
			return ( false ) ;
		}
		SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
		if ( FALSE == ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
		{
			CloseHandle( hFile ) ;
			return ( false ) ;

		}
		CloseHandle ( hFile ) ;
		dwSizeOfImage = NTFileHeader . OptionalHeader . SizeOfImage ;
		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CFakeSecurityAlertWorm::GetSizeOfImage, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckMemDetails
	In Parameters	: const CString& , HANDLE , HMODULE 
	Out Parameters	: bool
	Purpose			: scan the process memory
	Author			: Shweta
	Description		: scan the module's memory from the process for some keywords
--------------------------------------------------------------------------------------*/
bool CFakeSecurityAlertWorm :: CheckMemDetails ( const CString& csFilename , HANDLE hProcess , HMODULE hModule )
{
	try
	{
		DWORD dwSizeOfImage = 0 ;
		SIZE_T dwBytesRead = 0 ;
		unsigned char * Buffer = NULL ;
		char * szSearchString1 = "http://antispyware-review.info" ;
		char * szSearchString2 = "http://bestnetwok.net" ;

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

		if ( StrNIStr ( Buffer , dwBytesRead , (UCHAR*) szSearchString1 , strlen ( szSearchString1 ) ) ||
			 StrNIStr ( Buffer , dwBytesRead , (UCHAR*) szSearchString2 , strlen ( szSearchString2 ) ) ) 
		{
			SendScanStatusToUI ( Special_File ,  m_ulSpyName , csFilename  ) ;
			SendScanStatusToUI ( Special_Process , m_ulSpyName , csFilename  ) ;
			m_bSplSpyFound = true ;
		}

		delete []Buffer ;
		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CFakeSecurityAlertWorm::CheckMemDetails, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsVersionTabPresent
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: check if the file has a version tab
	Author			: Shweta
	Description		: return if the file has a version tab
--------------------------------------------------------------------------------------*/
bool CFakeSecurityAlertWorm :: IsVersionTabPresent ( const CString& csFileName )
{
	try
	{
		CFileVersionInfo	objFileVersionInfo;
		return objFileVersionInfo . DoTheVersionJob ( csFileName , false ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CFakeSecurityAlertWorm::IsVersionTabPresent, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetStopStatus
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: returns if the scanning is to be stopped
	Author			: Shweta
	Description		: returns if the stop button on the UI was clicked
--------------------------------------------------------------------------------------*/
bool CFakeSecurityAlertWorm :: GetStopStatus()
{
	return IsStopScanningSignaled() ;
}

bool CFakeSecurityAlertWorm :: CollectRunEntries()
{
	try
	{
		CStringArray csArrValues , csArrUnused ;
		CString csData , csSid;
		CStringArray csArrLoc ;
		CExecuteProcess objExeProc;

		csSid = objExeProc.GetCurrentUserSid();
		csArrLoc.Add ( RUN_REG_PATH );
		if ( m_bScanOtherLocations )
			csArrLoc.Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) );

		for ( int iloc = 0 ; iloc < csArrLoc.GetCount() ; iloc++ )
		{

			m_csArrRunEntries  . RemoveAll() ;
			m_objReg . QueryDataValue ( csSid + BACK_SLASH + csArrLoc.GetAt ( iloc ) , csArrValues , csArrUnused , HKEY_USERS ) ;
			if ( 0 >= csArrValues.GetCount() )
				return ( false ) ;

			for ( int i = 0 ; i < csArrValues . GetCount() ; i++ )
			{
				csData = csArrUnused.GetAt(i);
				csData.MakeLower();
				if ( csData .Find ( _T("\\system32\\") ) == -1 )
					continue;

				if ( _taccess_s ( csArrUnused.GetAt(i) , 0 ) != 0)
					continue;
		
				if ( IsVersionTabPresent( csArrUnused.GetAt(i) ) )
				{
					m_csArrRunEntries . Add ( csData . MakeLower() ) ;
				}
				else
					continue ;
			}
		}
		return (( m_csArrRunEntries.GetCount() == 0 ) ? false : true ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CFakeSecurityAlertWorm::CollectSTSEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}