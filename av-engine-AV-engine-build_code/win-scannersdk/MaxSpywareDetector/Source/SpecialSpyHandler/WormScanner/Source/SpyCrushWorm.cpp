/*===============================================================================
   FILE				: SpyCrushWorm.Cpp
   ABSTRACT			: implementation of Special Spyware SpyCrush Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 20/06/2007
   NOTES			:
   VERSION HISTORY	: 
					Version: 2.5.0.2
					Resource: Anand
					Description: added fix for the share task scheduler random dll

					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability				
=============================================================================*/

#include "pch.h"
#include "SpyCrushWorm.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: SC_ProcessModuleHandler
	In Parameters	: DWORD , HANDLE , HMODULE , LPCTSTR , LPVOID , bool
	Out Parameters	: bool
	Purpose			: callback function whichi is called for every module of the given ID
	Author			: Anand
	Description		: checks if the module is in the list of files we are currently searching
--------------------------------------------------------------------------------------*/
BOOL CALLBACK SC_ProcessModuleHandler ( DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CSpyCrushWorm * pSpyCrushWorm = (CSpyCrushWorm*) pThis ;

		bStopEnum = pSpyCrushWorm -> GetStopStatus() ;
		for ( int i = 0 ; i < pSpyCrushWorm -> m_csArrSTSEntries . GetCount() ; i++ )
		{
			if ( CString ( szModulePath ) . MakeLower() == pSpyCrushWorm -> m_csArrSTSEntries [ i ] )
			{
				if ( !pSpyCrushWorm -> IsVersionTabPresent ( pSpyCrushWorm -> m_csArrSTSEntries [ i ] ) )
					continue ;

				pSpyCrushWorm -> CheckMemDetails ( pSpyCrushWorm -> m_csArrSTSEntries [ i ] , hProcess , hModule ) ;
			}
		}

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
	Function		: SC_ProcessHandler
	In Parameters	: LPCTSTR , LPCTSTR , DWORD , HANDLE, LPVOID , bool 
	Out Parameters	: bool
	Purpose			: callback function whichi is called for every process
	Author			: Anand
	Description		: checks if the process is explorer.exe and enumerates its modules
--------------------------------------------------------------------------------------*/
BOOL CALLBACK SC_ProcessHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CSpyCrushWorm * pSpyCrushWorm = (CSpyCrushWorm*) pThis ;

		bStopEnum = pSpyCrushWorm -> GetStopStatus() ;

		if ( CString ( szExeName ) . MakeLower() == _T("explorer.exe") )
		{
			pSpyCrushWorm -> m_objEnumProc . EnumProcessModuleList ( dwProcessID , szExePath, (PROCESSMODULEHANDLER)SC_ProcessModuleHandler , pThis ) ;
		}

		return ( TRUE ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in SpyCrushWorm, SC_ProcessHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool , CFileSignatureListManager*
	Out Parameters	: bool
	Purpose			: Checks and removes spycrush random dll
	Author			: Anand
	Description		: Checks for entries in ShareTaskScheduler and scans explorer's memory
--------------------------------------------------------------------------------------*/
bool CSpyCrushWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( bToDelete )
		{
			for ( int i = 0 ; i < m_csArrInfectedFiles . GetCount() ; i++ )
				MoveFileEx ( m_csArrInfectedFiles [ i ] , NULL , MOVEFILE_DELAY_UNTIL_REBOOT ) ;
		}
		else
		{
			m_csArrInfectedFiles . RemoveAll() ;

			if ( !CollectSTSEntries() )
				return ( false ) ;

			m_objEnumProc . EnumRunningProcesses ( (PROCESSHANDLER) SC_ProcessHandler , (LPVOID)this ) ;
			if ( 0 >= m_csArrInfectedFiles . GetCount() )
				return ( false ) ;

			for ( int i = 0 ; i < m_csArrInfectedFiles . GetCount() ; i++ )
				SendScanStatusToUI ( Special_File , m_ulSpyName , m_csArrInfectedFiles [ i ]  ) ;

			m_bSplSpyFound = true ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch (...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyCrushWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetStopStatus
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: returns if the scanning is to be stopped
	Author			: Anand
	Description		: returns if the stop button on the UI was clicked
--------------------------------------------------------------------------------------*/
bool CSpyCrushWorm :: GetStopStatus()
{
	return IsStopScanningSignaled() ;
}

/*-------------------------------------------------------------------------------------
	Function		: CollectSTSEntries
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: collect STS entries
	Author			: Anand
	Description		: make a list of all the files in share task scheduler key
--------------------------------------------------------------------------------------*/
bool CSpyCrushWorm :: CollectSTSEntries()
{
	try
	{
		CStringArray csArrValues , csArrUnused ;
		CString csData ;

		m_csArrSTSEntries . RemoveAll() ;

		CStringArray csArrLocations ;

		csArrLocations . Add ( STS_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add  ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_STS_PATH) ) ;

		for ( int j = 0 ; j < csArrLocations . GetCount() ; j++ )
		{
			m_objReg . QueryDataValue ( csArrLocations [ j ] , csArrValues , csArrUnused , HKEY_LOCAL_MACHINE ) ;
			if ( 0 >= csArrValues.GetCount() )
				return ( false ) ;

			for ( int i = 0 ; i < csArrValues . GetCount() ; i++ )
			{
				m_objReg . Get ( CLSID_KEY + csArrValues [ i ] + _T("\\InProcServer32") , BLANKSTRING , csData , HKEY_LOCAL_MACHINE ) ;
				if ( csData . IsEmpty() )
					continue ;

				m_csArrSTSEntries . Add ( csData . MakeLower() ) ;
			}
		}

		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyCrushWorm::CollectSTSEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSizeOfImage
	In Parameters	: const char * , DWORD& 
	Out Parameters	: bool
	Purpose			: get the image size of the given file
	Author			: Anand
	Description		: read the PE structure of the file and determine the image size
--------------------------------------------------------------------------------------*/
bool CSpyCrushWorm :: GetSizeOfImage ( LPCTSTR szImageFilename , DWORD& dwSizeOfImage )
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
			CloseHandle( hFile );
			return ( false );
		}
		
		SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
		
		if ( FALSE == ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
		{
			CloseHandle( hFile );
			return ( false );
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

	return ( FALSE ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckMemDetails
	In Parameters	: const CString& , HANDLE , HMODULE 
	Out Parameters	: bool
	Purpose			: scan the process memory
	Author			: Anand
	Description		: scan the module's memory from the process for some keywords
--------------------------------------------------------------------------------------*/
bool CSpyCrushWorm :: CheckMemDetails ( const CString& csFilename , HANDLE hProcess , HMODULE hModule )
{
	try
	{
		DWORD dwSizeOfImage = 0 ;
		SIZE_T dwBytesRead = 0 ;
		unsigned char * Buffer = NULL ;
		char * szSearchString1 = "spyware applications that may impact the performance of your computer" ;
		char * szSearchString2 = "System Alert!" ;
		char * szSearchString3 = "Click the icon to get rid of unwanted spyware" ;

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
			 StrNIStr ( Buffer , dwBytesRead , (UCHAR*) szSearchString2 , strlen ( szSearchString1 ) ) || 
			 StrNIStr ( Buffer , dwBytesRead , (UCHAR*) szSearchString3 , strlen ( szSearchString1 ) ) )
		{
			m_csArrInfectedFiles . Add ( csFilename ) ;
		}

		delete []Buffer ;
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
	Function		: CheckMemDetails
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: check if the file has a version tab
	Author			: Anand
	Description		: return if the file has a version tab
--------------------------------------------------------------------------------------*/
bool CSpyCrushWorm :: IsVersionTabPresent ( const CString& csFileName )
{
	try
	{
		CFileVersionInfo	objFileVersionInfo;
		return objFileVersionInfo . DoTheVersionJob ( csFileName , false ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyCrushWorm::IsVersionTabPresent, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}
