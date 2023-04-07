/*====================================================================================
   FILE				: GenHostScanner.cpp
   ABSTRACT			: This class is used for scanning and qurantining generic entries in host file
   DOCUMENTS		: No documentation, as its a temporary scanner, has to be removed from Special Spyware, and to be put in main SD scanner
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created in 2008 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#include "pch.h"
#include "GenHostScanner.h"
#include "Cryptor.h"
#include "S2U.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool, CFileSignatureDb*
	Out Parameters	: bool
	Purpose			: scan host file
	Author			: Anand Srivastava
	Description		: scan host file for legitimate sites and remove them in quarantine
--------------------------------------------------------------------------------------*/
bool CGenHostScanner::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan ;

		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		if ( CheckHostFile ( bToDelete ) )
			m_bSplSpyFound = true ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CGenHostScanner::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool, CFileSignatureDb*
	Out Parameters	: bool
	Purpose			: scan host file
	Author			: Anand Srivastava
	Description		: scan host file for legitimate sites and remove them in quarantine
--------------------------------------------------------------------------------------*/
bool CGenHostScanner :: CheckHostFile ( bool bToDelete )
{
	try
	{
		if ( !bToDelete )
		{
			FILE * fp = NULL ;
			CS2U objHostFileDB ( false ) ;
			CString csHostFileName ;
			TCHAR szLine [ MAX_PATH ] = { 0 } ;
			TCHAR szDomainName [ MAX_PATH ] = { 0 } ;

			CRegistry oReg;
			CString csMaxDBPath;
			oReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
			if(!objHostFileDB.Load(csMaxDBPath + SD_DB_HOST))
				return ( false ) ;

			csHostFileName = CSystemInfo :: m_strSysDir + _T ( "\\drivers\\etc\\hosts" ) ;

			m_csArrLinesToRemove . RemoveAll() ;

			// opening in read/write mode to confirm that we have write access
			// as we will need this write access at the time of repair
			_tfopen_s ( &fp , csHostFileName , _T ( "r+" ) ) ;
			if ( !fp )
				return ( false ) ;

			while ( !feof ( fp ) )
			{
				memset ( szLine , 0 , sizeof ( szLine ) ) ;
				if ( NULL == _fgetts ( szLine , _countof ( szLine ) , fp ) )
					break ;

				if ( 0 == szLine [ 0 ] )
					break ;

				if ( _T ( '#' ) == szLine [ 0 ] )
					continue ;

				if ( 0x0 != szLine [ _countof ( szLine ) - 2 ] && 0xA != szLine [ _countof ( szLine ) - 2 ] )
					continue ;

				while (	( szLine [ 0 ] != 0x0 ) && (
						( szLine [ _tcslen ( szLine ) - 1 ] == 0x0A ) || 
						( szLine [ _tcslen ( szLine ) - 1 ] == 0x0D ) || 
						( szLine [ _tcslen ( szLine ) - 1 ] == 0x20 ) ) )
					szLine [ _tcslen ( szLine ) - 1 ] = 0x0 ;

				memset ( szDomainName , 0 , sizeof ( szDomainName ) ) ;
				if ( !GetDomainName ( szLine , szDomainName , _countof ( szDomainName ) ) )
					continue ;

				if ( objHostFileDB .SearchItem ( szDomainName ,NULL ) )
				{
					m_csArrLinesToRemove . Add ( szLine ) ;
					SendScanStatusToUI ( Special_File , m_ulSpyName , CString ( _T ( "HostFile, Blocked domain: " ) ) + szDomainName ) ; 
				}
			}

			fclose ( fp ) ;
			return ( m_csArrLinesToRemove . GetCount() > 0 ) ;
		}
		else
		{
			FILE * fpReader = NULL ;
			FILE * fpWriter = NULL ;
			CString csHostFileName ;
			CString csTempFileName ;
			TCHAR szLine [ MAX_PATH ] = { 0 } ;
			INT_PTR i = 0 ;
			INT_PTR iTotalItems = m_csArrLinesToRemove . GetCount() ;

			csHostFileName = CSystemInfo :: m_strSysDir + _T ( "\\drivers\\etc\\hosts" ) ;
			csTempFileName = csHostFileName + _T ( "_SD.00" ) ;
			if ( !_taccess ( csTempFileName , 0 ) )
				return ( false ) ;

			_tfopen_s ( &fpReader , csHostFileName , _T ( "r" ) ) ;
			_tfopen_s ( &fpWriter , csTempFileName , _T ( "a" ) ) ;
			if ( !fpReader || !fpWriter )
			{
				if ( fpReader ) fclose ( fpReader ) ;
				if ( fpWriter ) fclose ( fpWriter ) ;
				_tremove ( csTempFileName ) ; //No need to check return value
				return ( false ) ;
			}

			while ( !feof ( fpReader ) )
			{
				memset ( szLine , 0 , sizeof ( szLine ) ) ;
				if ( NULL == _fgetts ( szLine , _countof ( szLine ) , fpReader ) )
					break ;

				if ( 0 == szLine [ 0 ] )
					break ;

				while ( ( szLine [ _tcslen ( szLine ) - 1 ] == 0x0A ) || 
						( szLine [ _tcslen ( szLine ) - 1 ] == 0x0D ) || 
						( szLine [ _tcslen ( szLine ) - 1 ] == 0x20 ) )
					szLine [ _tcslen ( szLine ) - 1 ] = 0x0 ;

				for ( i = 0 ; i < iTotalItems ; i++ )
				{
					// break the loop when matching entry found
					if ( !_tcsicmp ( szLine , m_csArrLinesToRemove . GetAt ( i ) ) )
						break ;

					// write the line when done comparing the last item
					if ( i + 1 == iTotalItems )
					{
						_fputts ( szLine , fpWriter ) ;
						_fputts ( _T ( "\r\n" ) , fpWriter ) ;
					}
				}
			}

			fclose ( fpReader ) ;
			fclose ( fpWriter ) ;
			if ( 0 == _tremove ( csHostFileName ) )
				_trename ( csTempFileName , csHostFileName ) ;//No need to check return value
			else
				_tremove ( csTempFileName ) ;//No need to check return value
			return ( true ) ;
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CGenHostScanner :: CheckHostFile, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDomainName
	In Parameters	: LPCTSTR , TCHAR* , DWORD
	Out Parameters	: bool
	Purpose			: get domain name from line read from file
	Author			: Anand Srivastava
	Description		: get domain name from line read from file
--------------------------------------------------------------------------------------*/
bool CGenHostScanner :: GetDomainName ( TCHAR * szLineFromFile , TCHAR * szDomainName , DWORD dwDomainNameSize )
{
	try
	{
		if ( !szLineFromFile )
			return ( false ) ;

		TCHAR* end = 0 ;
		TCHAR* start = 0 ;

		end = start = szLineFromFile + ( _tcslen ( szLineFromFile ) - 1 ) ;
		while ( start )
		{
			if ( 0 == *start )
				break ;
			
			if ( start <= szLineFromFile )
				break ;

			if ( !isalnum ( *start ) && ( *start != _T ( '.' ) ) )
				break ;

			start-- ;
		}

		start++ ;

		if ( (DWORD) ( end - start ) >= dwDomainNameSize )
			return ( false ) ;

		_tcscpy_s ( szDomainName , dwDomainNameSize , start ) ;
		return ( true ) ;
	}

	catch(...)
	{
		AddLogEntry ( _T ( "Exception caught CGenHostScanner :: GetDomainName" ) ) ;
	}

	return ( false ) ;
}

