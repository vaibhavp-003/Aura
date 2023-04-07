/*======================================================================================
FILE             : GeneralServices.cpp
ABSTRACT         : Contains the implementation of general services
DOCUMENTS	     : Refer VSS Documents folder for details
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created in 2009 as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 10/07/2009 12:30 PM
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#include "stdafx.h"
#include "Logger.h"
#include "GeneralServices.h"
#include <aclapi.h>
#include "ziparchive.h"
#include "Tlhelp32.h"
#include "atlbase.h"
#include "MaExecConst.h"

SECURITY_ATTRIBUTES CGeneralServices::m_sa = { 0 } ;
PSID CGeneralServices::m_pEveryoneSID = NULL ;
PSID CGeneralServices::m_pAdminSID = NULL ;
PACL CGeneralServices::m_pACL = NULL ;
PSECURITY_DESCRIPTOR CGeneralServices::m_pSD = NULL ;

CGeneralServices :: CGeneralServices()
{
}

CGeneralServices :: ~CGeneralServices()
{
}

bool CGeneralServices :: ExecuteApplication ( LPCTSTR szFullAppName , LPTSTR szCmdLineParam , bool bHideWindow ,
											  DWORD dwWaitForAppMS , LPDWORD pdwThreaID , LPDWORD pdwProcessID )
{
	STARTUPINFO StartupInfo = { 0 } ;
	PROCESS_INFORMATION ProcessInfo = { 0 } ;
	DWORD dwCreationFlags = 0 ;
	TCHAR szCmdLineParamDup [ MAX_PATH * 2 ] = { 0 } ;

	StartupInfo . cb = sizeof ( StartupInfo ) ;

	if ( bHideWindow )
	{
		dwCreationFlags = CREATE_NO_WINDOW ;
		StartupInfo . dwFlags = STARTF_USESHOWWINDOW ;
		StartupInfo . wShowWindow = SW_HIDE ;
	}

	if ( szCmdLineParam )
	{
		if ( ( _tcslen ( szFullAppName ) + _tcslen ( szCmdLineParam ) + 4 ) >= _countof ( szCmdLineParamDup ) )
			return ( false ) ;

		_stprintf_s ( szCmdLineParamDup , _countof ( szCmdLineParamDup ) , _T("\"%s\" %s") , szFullAppName , szCmdLineParam ) ;
	}
	else
	{
		if ( ( _tcslen ( szFullAppName ) + 4 ) >= _countof ( szCmdLineParamDup ) )
			return ( false ) ;

		_tcscpy_s ( szCmdLineParamDup , _countof ( szCmdLineParamDup ) , szFullAppName  ) ;
	}

	if ( ! CreateProcess ( NULL , szCmdLineParamDup , 0 , 0 , FALSE , dwCreationFlags , 0 , 0 , &StartupInfo , &ProcessInfo ) )
	{
		return ( false ) ;
	}

	if ( dwWaitForAppMS )
	{
		if ( MAXDWORD == dwWaitForAppMS )
		{
			WaitForSingleObject ( ProcessInfo . hProcess , INFINITE ) ;
		}
		else
		{
			WaitForSingleObject ( ProcessInfo . hProcess , dwWaitForAppMS ) ;
			TerminateProcess ( ProcessInfo . hProcess , 0 ) ;
			WaitForSingleObject ( ProcessInfo . hProcess , INFINITE ) ;
		}
	}

	if ( NULL != pdwThreaID )
	{
		*pdwThreaID = ProcessInfo . dwThreadId ;
	}

	if ( NULL != pdwProcessID )
	{
		*pdwProcessID = ProcessInfo . dwProcessId ;
	}

	CloseHandle ( ProcessInfo . hThread ) ;
	CloseHandle ( ProcessInfo . hProcess ) ;	
	return ( true ) ;
}

bool CGeneralServices :: FormatString ( LPTSTR szOutput , DWORD dwOutputElementsCount , LPCTSTR szFormat , ... )
{
	va_list args ;
	DWORD dwRequiredLength = 0 ;

	va_start ( args , szFormat ) ;
	dwRequiredLength = _vsctprintf ( szFormat , args ) ;
	if ( dwRequiredLength >= dwOutputElementsCount )
		return ( false ) ;

	memset ( szOutput , 0 , dwOutputElementsCount * sizeof ( TCHAR ) ) ;
	_vstprintf_s ( szOutput , dwOutputElementsCount , szFormat , args ) ;
	return ( true ) ;
}

bool CGeneralServices :: SetRegistryValue ( HKEY hHive , LPCTSTR szFullKeyName , LPCTSTR szValueName , LPCTSTR szData )
{
	LONG iRetValue = 0 ;
	HKEY hKey = 0 ;
	DWORD dwDataSize = 0 ;

	iRetValue = RegOpenKeyEx ( hHive , szFullKeyName ,  0 , KEY_SET_VALUE , &hKey ) ;
	if ( ERROR_SUCCESS != iRetValue )
		return ( false ) ;

	dwDataSize = ( _tcslen ( szData ) + 1 ) * sizeof ( TCHAR ) ;
	iRetValue = RegSetValueEx ( hKey , szValueName , 0 , REG_SZ , (const BYTE*)szData , dwDataSize ) ;
	if ( ERROR_SUCCESS != iRetValue )
	{
		RegCloseKey ( hKey ) ;
		return ( false ) ;
	}

	RegCloseKey ( hKey ) ;
	return ( true ) ;
}

bool CGeneralServices :: GetRegistryValue ( HKEY hHive , LPCTSTR szFullKeyName , LPCTSTR szValueName , LPTSTR szData , DWORD dwDataElementsCount )
{
	LONG iRetValue = 0 ;
	HKEY hKey = 0 ;

	iRetValue = RegOpenKeyEx ( hHive , szFullKeyName ,  0 , KEY_READ , &hKey ) ;
	if ( ERROR_SUCCESS != iRetValue )
		return ( false ) ;

	dwDataElementsCount = dwDataElementsCount * sizeof ( TCHAR ) ;
	iRetValue = RegQueryValueEx ( hKey , szValueName , 0 , 0 , (LPBYTE)szData , &dwDataElementsCount ) ;
	if ( ERROR_SUCCESS != iRetValue )
	{
		RegCloseKey ( hKey ) ;
		return ( false ) ;
	}

	RegCloseKey ( hKey ) ;
	return ( true ) ;
}

bool CGeneralServices :: ChangePCTime ( LPSYSTEMTIME lpNewSystemTime )
{
	if ( ! SetLocalTime ( lpNewSystemTime ) )
		return ( false ) ;

	return ( true ) ;
}

bool CGeneralServices :: ChangePCName ( LPCTSTR szNewName )
{
	HKEY hKey = NULL ;

	if ( ! SetComputerName ( szNewName ) )
	{
		g_objLogApp.AddLog1( _T ( "SetComputerName failed for name:[%s], GLE:[%i]" ) , szNewName , GetLastError() ) ;
		return ( false ) ;
	}

	if ( ! SetRegistryValue ( HKEY_LOCAL_MACHINE , KEY_PARAMETERS , _T ( "Hostname" ) , szNewName ) )
	{
		g_objLogApp.AddLog1( _T ( "SetRegistryValue failed for value:[Hostname], data:[%s]" ) , szNewName ) ;
		return ( false ) ;
	}

	if ( ! SetRegistryValue ( HKEY_LOCAL_MACHINE , KEY_PARAMETERS , _T ( "NV Hostname" ) , szNewName ) )
	{
		g_objLogApp.AddLog1( _T ( "SetRegistryValue failed for value:[NV Hostname], data:[%s]" ) , szNewName ) ;
		return ( false ) ;
	}

	return ( true ) ;
}

bool CGeneralServices :: ChangePCIPAddress ( LPCTSTR szIPAddress )
{
	bool bChangeIPSuccess = true ;
	HKEY hKey = NULL ;
	LONG iRetValue = 0 ;
	DWORD dwKeyNameSize = 0 ;
	TCHAR szSubKeyName [ MAX_PATH ] = { 0 } ;
	TCHAR szFullKeyName [ MAX_PATH ] = { 0 } ;
	TCHAR szData [ MAX_PATH ] = { 0 } ;

	iRetValue = RegOpenKeyEx ( HKEY_LOCAL_MACHINE , KEY_NETWORK_CARDS , 0 , KEY_ENUMERATE_SUB_KEYS , &hKey ) ;
	if ( ERROR_SUCCESS != iRetValue )
	{
		g_objLogApp.AddLog1( _T ( "RegOpenKeyEx failed for key:[%s], GLE:[%i]" ) , KEY_NETWORK_CARDS , GetLastError() ) ;
		return ( false ) ;
	}

	for ( int i = 0 ; ; i++ )
	{
		dwKeyNameSize = _countof ( szSubKeyName ) ;
		memset ( szSubKeyName , 0 , sizeof ( szSubKeyName ) ) ;

		iRetValue = RegEnumKeyEx ( hKey , i , szSubKeyName , &dwKeyNameSize , 0 , 0 , 0 , 0 ) ;
		if ( ERROR_SUCCESS != iRetValue )
			break ;

		if ( ! FormatString ( szFullKeyName , _countof ( szFullKeyName ) , _T("%s\\%s") , KEY_NETWORK_CARDS , szSubKeyName ) )
			continue ;

		if ( ! GetRegistryValue ( HKEY_LOCAL_MACHINE , szFullKeyName , _T ( "ServiceName" ) , szData , _countof ( szData ) ) )
		{
			bChangeIPSuccess = false ;
			break ;
		}

		if ( ! FormatString ( szFullKeyName , _countof ( szFullKeyName ) , _T("%s\\%s") , KEY_INTERFACES , szData ) )
			continue ;

		if ( ! SetRegistryValue ( HKEY_LOCAL_MACHINE , szFullKeyName , _T ( "IPAddress" ) , szIPAddress ) )
		{
			bChangeIPSuccess = false ;
			break ;
		}
	}

	RegCloseKey ( hKey ) ;
	return ( bChangeIPSuccess ) ;
}

void CGeneralServices::GetCurrDateTime(TCHAR *szDateTime, int iBuffSize)
{
	time_t rawtime = {0};
	struct tm timeinfo = {0};
	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	_tcsftime(szDateTime, iBuffSize, _T("%Y-%m-%d %H:%M:%S"), &timeinfo);
}

bool CGeneralServices :: RebootSystem ( DWORD dwType )
{
    try
    {
        HANDLE hToken; 
        TOKEN_PRIVILEGES tkp;                                        
        // Get a token for this process. 
        if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            // Get the LUID for the shutdown privilege. 
            LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid); 

			tkp.PrivilegeCount = 1;  // one privilege to set    
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

            // Get the shutdown privilege for this process. 
            AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); 
        }

        if ( dwType == 0 )
        {
            // Shut down the system and force all applications to close. 
            if(!ExitWindowsEx(EWX_REBOOT| EWX_FORCE, 0))
            {
                return false;
            }
        }

        if ( dwType == 1 )
        {
            if(!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0))
            {   
                return false;
            }
        }

        if ( dwType == 2 )
        {
            if(!ExitWindowsEx(EWX_LOGOFF| EWX_FORCE, 0))
            {
                return false;
                
            }
        }

		return ( true ) ;
    }

    catch(...)
    {
		g_objLogApp.AddLog1(_T("Exception in CGeneralServices::RebootSystem"));
		return ( false ) ;
    }
}

bool CGeneralServices :: SetTokenPrivilege ( LPCTSTR szPrivilegeName )
{
	BOOL bSuccess = FALSE ;
	HANDLE hToken = NULL ;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 } ;

	if ( ! OpenProcessToken ( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY , &hToken ) )
		return ( false ) ;

	if ( ! LookupPrivilegeValue ( NULL , szPrivilegeName , & TokenPrivileges . Privileges [ 0 ] . Luid ) )
	{
		CloseHandle ( hToken ) ;
		return ( false ) ;
	}

	TokenPrivileges . PrivilegeCount = 1 ;
	TokenPrivileges . Privileges [ 0 ] . Attributes = SE_PRIVILEGE_ENABLED ;

	if ( ! AdjustTokenPrivileges ( hToken , FALSE , & TokenPrivileges , 0 , (PTOKEN_PRIVILEGES)NULL , 0 ) )
	{
		CloseHandle ( hToken ) ;
		return ( false ) ;
	}

	CloseHandle ( hToken ) ;
	return ( true ) ;
}

bool CGeneralServices :: LoadOtherUsersHive ( LPVOID lpParam )
{
	bool bSuccess = true ;
	HKEY hKey = NULL , hTempKey = NULL ;
	LONG iRetValue = 0 ;
	DWORD dwKeyNameSize = 0 ;
	TCHAR szSubKeyName [ MAX_PATH ] = { 0 } ;
	TCHAR szFullName [ MAX_PATH ] = { 0 } ;
	TCHAR szData [ MAX_PATH ] = { 0 } ;

	SetTokenPrivilege ( SE_RESTORE_NAME ) ;
	SetTokenPrivilege ( SE_BACKUP_NAME ) ;

	iRetValue = RegOpenKeyEx ( HKEY_LOCAL_MACHINE , KEY_PROFILE_LIST , 0 , KEY_ENUMERATE_SUB_KEYS , &hKey ) ;
	if ( ERROR_SUCCESS != iRetValue )
		return ( false ) ;

	for ( int i = 0 ; ; i++ )
	{
		dwKeyNameSize = _countof ( szSubKeyName ) ;
		memset ( szSubKeyName , 0 , sizeof ( szSubKeyName ) ) ;

		iRetValue = RegEnumKeyEx ( hKey , i , szSubKeyName , &dwKeyNameSize , 0 , 0 , 0 , 0 ) ;
		if ( ERROR_SUCCESS != iRetValue )
		{
			break ;
		}

		if ( ERROR_SUCCESS == RegOpenKeyEx ( HKEY_USERS , szSubKeyName , 0 , KEY_READ , &hTempKey ) )
		{
			RegCloseKey ( hTempKey ) ;
			continue ;
		}

		if ( ! FormatString ( szFullName , _countof ( szFullName ) , _T("%s\\%s") , KEY_PROFILE_LIST , szSubKeyName ) )
		{
			bSuccess = false ;
			break ;
		}

		if ( ! GetRegistryValue ( HKEY_LOCAL_MACHINE , szFullName , _T("ProfileImagePath") , szData , _countof ( szData ) ) )
		{
			bSuccess = false ;
			break ;
		}

		if ( ! ExpandEnvironmentStrings ( szData , szData , _countof ( szData ) ) )
		{
			bSuccess = false ;
			break ;
		}

		if ( ! FormatString ( szFullName , _countof ( szFullName ) , _T("%s\\NTUSER.DAT") , szData ) )
		{
			bSuccess = false ;
			break ;
		}

		if ( ERROR_SUCCESS != RegLoadKey ( HKEY_USERS , szSubKeyName , szFullName ) )
		{
			bSuccess = false ;
			break ;
		}
	}

	RegCloseKey ( hKey ) ;
	return ( bSuccess ) ;
}

bool CGeneralServices :: InitSecurityAttribute()
{
	DWORD dwRes;
    EXPLICIT_ACCESS ea[2];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
  
    // Create a well-known SID for the Everyone group.
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
								 SECURITY_WORLD_RID,
								 0, 0, 0, 0, 0, 0, 0,
								 &m_pEveryoneSID))
    {
		g_objLogApp.AddLog1( _T ( "AllocateAndInitializeSid Error %u" ) , GetLastError() ) ;
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);

		return ( false ) ;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = KEY_ALL_ACCESS | SYNCHRONIZE;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance= NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName  = (LPTSTR) m_pEveryoneSID;

    // Create a SID for the BUILTIN\Administrators group.
    if(! AllocateAndInitializeSid(&SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_ADMINS,
                     0, 0, 0, 0, 0, 0,
                     &m_pAdminSID)) 
    {
		g_objLogApp.AddLog1( _T ( "AllocateAndInitializeSid Error %u" ) , GetLastError() ) ;
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);

		return ( false ) ;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow the Administrators group full access to
    // the key.
    ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance= NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName  = (LPTSTR) m_pAdminSID;

    // Create a new ACL that contains the new ACEs.
    dwRes = SetEntriesInAcl(2, ea, NULL, &m_pACL);
    if (ERROR_SUCCESS != dwRes) 
    {
		g_objLogApp.AddLog1( _T ( "SetEntriesInAcl Error %u" ) , GetLastError() ) ;
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);

		return ( false ) ;
	}

    // Initialize a security descriptor.  
    m_pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH); 
    if (NULL == m_pSD) 
    { 
		g_objLogApp.AddLog1( _T ( "LocalAlloc Error %u" ) , GetLastError() ) ;
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);

		return ( false ) ;
    } 
 
    if (!InitializeSecurityDescriptor(m_pSD, SECURITY_DESCRIPTOR_REVISION)) 
    {  
		g_objLogApp.AddLog1( _T ( "InitializeSecurityDescriptor Error %u" ) , GetLastError() ) ;
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);

		return ( false ) ;
    } 
 
    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl( m_pSD, 
									TRUE,     // bDaclPresent flag   
									m_pACL, 
									FALSE))   // not a default DACL 
    {  
		g_objLogApp.AddLog1( _T ( "SetSecurityDescriptorDacl Error %u" ) , GetLastError() ) ;
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);

		return ( false ) ;
    }

    // Initialize a security attributes structure.
    m_sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    m_sa.lpSecurityDescriptor = m_pSD;
    m_sa.bInheritHandle = FALSE;
	return ( true ) ;
}

bool CGeneralServices :: WaitForNetworkActivity ( DWORD dwMaxTimeToWait )
{
	HANDLE hEventHandle = NULL ;
	DWORD dwResult = 0 ;

	if ( ! InitSecurityAttribute() )
	{
		g_objLogApp.AddLog1( _T ( "InitSecurityAttribute failed" ) ) ;
		return ( false ) ;
	}

	hEventHandle = CreateEvent ( &m_sa , FALSE , FALSE , _EVENT_NOTIFY_AUTOMATION_ ) ;
	if ( NULL == hEventHandle )
		return ( false ) ;

	dwResult = WaitForSingleObject ( hEventHandle , dwMaxTimeToWait ) ;
	if ( WAIT_OBJECT_0 == dwResult )
	{
		g_objLogApp.AddLog1( _T ( "No Network Activity found" ) ) ;
		ResetEvent ( hEventHandle ) ;
	}
	else if ( WAIT_TIMEOUT == dwResult )
	{
		g_objLogApp.AddLog1( _T ( "Network activiy max wait limit reached: %u ms" ) , dwMaxTimeToWait ) ;
	}

	CloseHandle ( hEventHandle ) ;
	if ( m_pEveryoneSID ) FreeSid ( m_pEveryoneSID ) ;
	if ( m_pAdminSID ) FreeSid ( m_pAdminSID ) ;
	if ( m_pACL ) LocalFree ( m_pACL ) ;
	if ( m_pSD ) LocalFree ( m_pSD ) ;
	return ( true ) ;
}


bool CGeneralServices :: GetAllFileNamesInPath ( CString csFolderName , CStringArray& csArrFilePath )
{
	BOOL bFiles = FALSE ;
	CFileFind Finder ;
	CString csTemp;

	bFiles = Finder.FindFile ( csFolderName + _T("\\*.*") ) ;

	while ( bFiles )
	{
		bFiles = Finder.FindNextFile() ;
		if ( Finder.IsDots() )
			continue ;

		if ( Finder.IsDirectory() )
		{
			GetAllFileNamesInPath ( csFolderName + _T("\\") + Finder.GetFileName() , csArrFilePath ) ;
		}
		else
		{
			OutputDebugString ( _T("\n Enumerated file ") + Finder.GetFileName() ) ;
			CString csTempStr = Finder.GetFileName() ;
			csTempStr.MakeLower();

			csTemp = csFolderName + _T("\\") + Finder.GetFileName();
			csArrFilePath.Add(csTemp.MakeLower()) ;
		}
	}

	Finder.Close() ;
	return ( true ) ;
}



bool CGeneralServices :: CompressFolder( CString csFolderName ,CString csZipName ,bool bDeleteAfterCompress ,bool bFinalZip )
{
	try
	{
		CZipArchive m_Arc;
		bool bErr = true ;
		CStringArray csArrFiles ;
		CString csZipFileName ( csFolderName ) ;

		g_objLogApp.AddLog1(_T(">>>>> Creating ZIP: ") + csZipName);
		OutputDebugString(_T("\n>>>>> Creating ZIP: ") + csZipName);
		
		GetAllFileNamesInPath ( csFolderName , csArrFiles ) ;

		if(csZipName.Right(4).CompareNoCase(L".zip") != 0)
		    csZipFileName = csZipName + _T(".zip");
        else
           csZipFileName =  csZipName;

		
		m_Arc.Open ( csZipFileName , CZipArchive::create , 0 ) ;

		m_Arc.SetPassword(_T("virus007")) ; //set password to Zip file.

		for ( int i = 0 ; i < csArrFiles.GetCount() ; i++ )
		{
			CString temp, csTempStr ;
			csTempStr = temp = csArrFiles [ i ] ;

			csTempStr.MakeLower() ;

			g_objLogApp.AddLog1(_T(">>>>> Adding File: ") + csArrFiles[i]);
			OutputDebugString(_T("\n>>>>> Adding File: ") + csArrFiles[i]);
			bErr = m_Arc . AddNewFile ( csArrFiles [ i ] ) ;

			if ( ! bErr )
				OutputDebugString(_T("\nError while adding in ZIP") + csTempStr );

			if ( bDeleteAfterCompress )
			{
				csTempStr.MakeLower();
				if ( csTempStr.Find(_T(".zip")) != -1 )
				{
					continue ;
				}

				DeleteFile ( csArrFiles [ i ]  ) ;
			}
		}
		
		m_Arc.Close() ;
		g_objLogApp.AddLog1(_T(">>>>> Closing Zip File: ") + csZipName);
		OutputDebugString(_T("\n>>>>> Closing Zip File: ") + csZipName);

		return ( true ) ;
	}
	catch (...)
	{
		g_objLogApp.AddLog1(_T("Exception in CompressFolder") ) ;
		//AfxMessageBox(_T("Exception in CompressFolder") ) ;
		return ( false ) ;
	}
}



bool CGeneralServices ::UnzipToFolder(const CString csFileToUnzip,TCHAR *csDestination,CString csPassword ,bool bDeleteAfterUncompressed)
{
	BOOL berr;
	try
	{
		CZipArchive m_Arc;
		berr = 0;
		
		OutputDebugString(_T("\n>>>>> UnZip File: ") + csFileToUnzip);

		m_Arc.Open(csFileToUnzip, CZipArchive::openReadOnly, 0 );
		int iCount = m_Arc.GetNoEntries();
		CString sz ;
		for(int i=0;i<iCount;i++)
		{
			CZipFileHeader fh;
			m_Arc.GetFileInfo(fh, (WORD)i);
			if ( csPassword.GetLength() != 0 && fh.IsEncrypted())
				m_Arc.SetPassword(csPassword);
			sz = (LPCTSTR)fh.GetFileName();
			DeleteFile((CString)csDestination + sz);
			m_Arc.ExtractFile((WORD)i, csDestination);
			if(_taccess_s((CString)csDestination + sz, 0) == 0)
				SetFileAttributes((CString)csDestination + sz, FILE_ATTRIBUTE_ARCHIVE);

			OutputDebugString(_T("\n>>>>> Extracted Successfully: ") + (CString)csDestination + sz);
		}

		int iPos = sz.ReverseFind(_T('\\'));
		wsprintf(csDestination,_T("%s\\%s"),csDestination, sz.Left(iPos));
		m_Arc.Close();

		OutputDebugString(_T("\n>>>>> Finished Unzip: ") + csFileToUnzip);

		if ( bDeleteAfterUncompressed )
			DeleteFile( csFileToUnzip );
	}
	catch (CException* e)
	{
		e->Delete();
		OutputDebugString(_T("\n>>>>> Exception caught while Unzip: ") + csFileToUnzip);
        //AfxMessageBox(_T("Exception in UnzipToFolder") ) ;
		return false;
	}
	return true;
}

bool CGeneralServices::CopyDirectory( LPCTSTR szExistingFolder , LPCTSTR szDestinationFolder )
{
	TCHAR szCommand[MAX_PATH] = {0};
	_stprintf_s(szCommand,_T("xcopy \"%s\\*.*\" \"%s\" /Y /Q /S /H /E "),szExistingFolder,szDestinationFolder);
	_tsystem(szCommand);

	return true;
}
bool CGeneralServices::CleanDirectory( LPCTSTR szDirectoryPath)
{
	TCHAR szCommand[MAX_PATH] = {0};
	_stprintf_s(szCommand,_T("del \"%s\" /Q"),szDirectoryPath);
	_tsystem(szCommand);
	return true;
}
bool CGeneralServices::DeleteDirectory( LPCTSTR szDirectoryPath)
{
	TCHAR szCommand[MAX_PATH] = {0};
	_stprintf_s(szCommand,_T("rd /s /q \"%s\""),szDirectoryPath);
	_tsystem(szCommand);
	return true;
}

bool CGeneralServices::KillProcessByID(DWORD ProcessID)
{
	HANDLE hResult;
	//to open an existing process
	hResult = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessID);
	if(hResult)
	{
		TerminateProcess(hResult, 0);
		::CloseHandle(hResult);
		return true;
	}
	return false;
	
}

/*-------------------------------------------------------------------------------------
	Function		: StartProcessWithToken
	In Parameters	: CString csProcessPath, CString csCommandLineParam , CString csAccessProcessName
	Out Parameters	: BOOL
	Purpose			: To Start process Service
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CGeneralServices::StartProcessWithToken(CString csProcessPath, CString csCommandLineParam ,CString csAccessProcessName , bool bWait)
{
	try
	{
		HANDLE				hToken = NULL;
		TOKEN_USER          oUser[16];
		DWORD               u32Needed;
		TCHAR               sUserName[256], domainName[256];
		DWORD               userNameSize, domainNameSize;
		SID_NAME_USE        sidType;

		ZeroMemory(oUser,sizeof(oUser));
		BOOL bRet = OpenProcessToken( GetExplorerProcessHandle( csAccessProcessName ), TOKEN_ALL_ACCESS, &hToken);
		if(!bRet)
		{
			return FALSE;
		}

		if(hToken == NULL)
		{
	
			if(csAccessProcessName.CompareNoCase(L"explorer.exe")!=0)
			//if(_tcsstr(csAccessProcessName, L"explorer.exe")!=0)
			{
				if(!OpenProcessToken( GetExplorerProcessHandle( L"explorer.exe" ), TOKEN_ALL_ACCESS, &hToken))
					return FALSE;
				
				if(hToken == NULL)
				{
					return FALSE;
				}
			}
		}

		GetTokenInformation(hToken, TokenUser, &oUser[0], sizeof(oUser), &u32Needed);
		userNameSize		= _countof (sUserName) - 1;
		domainNameSize      = _countof (domainName) - 1;
		
		LookupAccountSid (NULL, oUser[0].User.Sid, sUserName, &userNameSize, domainName, &domainNameSize, &sidType);
		HDESK       hdesk = NULL;
		HWINSTA     hwinsta = NULL, hwinstaSave = NULL;
		PROCESS_INFORMATION pi;
		PSID pSid = NULL;
		STARTUPINFO si;
		BOOL bResult = FALSE;
		CString csErr;

		// Save a handle to the caller's current window station.
		if ( (hwinstaSave = GetProcessWindowStation() ) == NULL)
		{
			CloseHandle(hToken);  
			return FALSE;
		}

		// Get a handle to the interactive window station.
		hwinsta = OpenWindowStation(
					_T("winsta0"),                   // the interactive window station 
					FALSE,							// handle is not inheritable
					READ_CONTROL | WRITE_DAC);		// rights to read/write the DACL
					
		if (hwinsta == NULL) 
		{
			SetProcessWindowStation (hwinstaSave);
			CloseHandle(hToken);  
			return FALSE;
		}

		// To get the correct default desktop, set the caller's 
		// window station to the interactive window station.
		if (!SetProcessWindowStation( hwinsta ))
		{
			SetProcessWindowStation (hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseHandle(hToken);  
			return FALSE;
		}

		// Get a handle to the interactive desktop.
		hdesk = OpenDesktop(
			  _T("default"),     // the interactive window station 
				0,             // no interaction with other desktop processes
				FALSE,         // handle is not inheritable
				READ_CONTROL | // request the rights to read and write the DACL
				WRITE_DAC | 
				DESKTOP_WRITEOBJECTS | 
				DESKTOP_READOBJECTS);

		if (hdesk == NULL) 
		{
			SetProcessWindowStation( hwinstaSave );
			CloseWindowStation( hwinsta );
			CloseHandle( hToken );  
			return FALSE;
		}

		// Restore the caller's window station.
		if (!SetProcessWindowStation(hwinstaSave)) 
		{
			SetProcessWindowStation (hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseDesktop(hdesk);
			CloseHandle(hToken);  
			return FALSE;
		}

		// Impersonate client to ensure access to executable file.
		if (! ImpersonateLoggedOnUser(hToken) ) 
		{
			SetProcessWindowStation (hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseDesktop(hdesk);
			CloseHandle(hToken); 
			return FALSE;
		}

		// Initialize the STARTUPINFO structure.
		// Specify that the process runs in the interactive desktop.
		ZeroMemory(	&si, sizeof(STARTUPINFO));
		si.cb		=  sizeof(STARTUPINFO);
		si.lpDesktop =  _T("winsta0\\default");

		TCHAR   csCmdParam[MAX_PATH] = {0}; 
		DWORD  dwSize = MAX_PATH;
		wcscpy_s(csCmdParam, _countof(csCmdParam), csCommandLineParam);

		bResult = CreateProcessAsUser(
				hToken,            // client's access token
				csProcessPath,     // file to execute
				csCmdParam,		 // command line
				NULL,              // pointer to process SECURITY_ATTRIBUTES
				NULL,              // pointer to thread SECURITY_ATTRIBUTES
				FALSE,             // handles are not inheritable
				NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,   // creation flags
				NULL,              // pointer to new environment block 
				NULL,              // name of current directory 
				&si,               // pointer to STARTUPINFO structure
				&pi                // receives information about new process
				); 
		
		if(bResult && bWait && pi.hProcess)		
		{
			
			::WaitForSingleObject(pi.hProcess  , 1000 * 60 * 2);				
			CloseHandle ( pi . hThread ) ;
			CloseHandle ( pi . hProcess ) ;
		}

	
		if(hwinstaSave)
			SetProcessWindowStation (hwinstaSave);
		if(hwinsta)
			CloseWindowStation(hwinsta);
		if(hdesk)
			CloseDesktop(hdesk);
		if(hToken)
			CloseHandle(hToken); 
		// End impersonation of client.
	
		RevertToSelf();
		return bResult ? true:false ;
	}
	catch(...)
	{
	   //AddLogEntry(_T("Exception caught in KeyLoggerScannerDll.cpp StartProcess "));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetExplorerProcessHandle
	In Parameters	: -
	Out Parameters	: HANDLE
	Purpose			: Needed to impersonate the logged in user...
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
HANDLE CGeneralServices ::GetExplorerProcessHandle(CString csAccessProcessName)  //Needed to impersonate the logged in user...
{
     HANDLE hSnapshot;
     PROCESSENTRY32 pe32;
     ZeroMemory(&pe32,sizeof(pe32));
     HANDLE temp = NULL;
     try
     {
		 
          hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
          pe32.dwSize = sizeof(PROCESSENTRY32); 
          if(Process32First(hSnapshot,&pe32))
          {
               do
               {
					CString csExeName = pe32.szExeFile;

					//if(_tcsstr(csExeName, csAccessProcessName)==0)
					if(csExeName.CompareNoCase(csAccessProcessName) == 0)
					{
						temp = OpenProcess (PROCESS_ALL_ACCESS,FALSE, pe32.th32ProcessID); 
						break;
					}
				   
               }while(Process32Next(hSnapshot,&pe32));
          }
		 
     }
     catch(...)
     {
		 //AddLogEntry(_T("Exception caught in CExecuteProcess::GetExplorerProcessHandle"));
     }
     return temp;
}

/*-------------------------------------------------------------------------------------
	Function		: 
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: 
--------------------------------------------------------------------------------------*/
bool CGeneralServices::GetRegDWORD( LPCTSTR strKeyPath, LPCTSTR strValueName, DWORD &dwValue, HKEY HiveRoot ) const
{
	CRegKey registryKey;
	
	if( registryKey.Open( HiveRoot, strKeyPath,KEY_READ ) != ERROR_SUCCESS)
		return false;
	
	if( registryKey.QueryDWORDValue( strValueName, dwValue) != ERROR_SUCCESS )
	{
		registryKey.Close();
		return false;
	}
	
	registryKey.Close();
	return true;
}



/*-------------------------------------------------------------------------------------
	Function		: 
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: 
--------------------------------------------------------------------------------------*/
bool CGeneralServices::SetRegDWORD(LPCTSTR strKeyPath, LPCTSTR strValueName, DWORD &o_dwValue, HKEY HiveRoot)const
{
	CRegKey registryKey;
	if( registryKey.Create(HiveRoot,strKeyPath) != ERROR_SUCCESS)
		return false;
	
	if( registryKey.SetDWORDValue(strValueName,o_dwValue) != ERROR_SUCCESS )
		return false;
	
	registryKey.Close();
	
	return true;
}

bool CGeneralServices::GetIPAddress(TCHAR * pIPAddress)
{
	try
	{
		
        char hostname[MAX_PATH] = {0};
		WORD wVer;
		WSADATA	wData;
		PHOSTENT hostinfo;
		wVer = MAKEWORD( 2,	0 );
		wsprintf(pIPAddress, _T("0.0.0.0") );
		// Get IP Address 
		if(WSAStartup(wVer, &wData) == 0)
		{
			if(gethostname(hostname, sizeof(hostname)) == 0)
			{
				if (strcmp(hostname,"")!= 0 && (hostinfo = gethostbyname(hostname)) != NULL)
				{
					char chIP[MAX_PATH] = {0};
					CString csTemp;
					strcpy_s(chIP , inet_ntoa(*(struct in_addr *)*hostinfo->h_addr_list));
					if( strlen(chIP) > 0 )
						wsprintf(pIPAddress, _T("%S") , chIP );
					WSACleanup(	); 
					return true;				
				}
			}
			WSACleanup(	); 						
		} 					
	}
	catch(...)
	{		
	}
	return false;	
}

bool CGeneralServices::ReadAndExecuteFilesFromDB()
{
	DWORD dwProcID = 0,dwThreadID = 0;
	bool bRet = false;

	g_objLogApp.AddLog1(_T("Launch Application: %s"), SPYLAUNCHER_EXE_PATH);
	if(PathFileExists(SPYLAUNCHER_EXE_PATH))
	{
		ExecuteApplication(SPYLAUNCHER_EXE_PATH, _T("AUTOTEMP"), false, 0, &dwThreadID, &dwProcID);
		bRet = true;
	}
	
	g_objLogApp.AddLog1(_T("Received Process ID: %d, Thread ID: %d"), dwThreadID, &dwProcID);

	Sleep(50);
	CRegKey objReg;
	objReg.Open(HKEY_LOCAL_MACHINE, _T("Software\\Automation_Mon"));
	objReg.SetDWORDValue(_T("PID"), dwProcID);
	objReg.Close();
	
	return bRet;
}

bool CGeneralServices :: CopyAllFilesToBinaryCollection()
{
	CS2U objFileNameDB(false);
	bool bFoundNewFiles = false;
	CString csInputFolderName = AUTOMATION_INPUTDATAPATH ;
	objFileNameDB.Load (FILESADDED_DB_PATH);

	g_objLogApp.AddLog1(_T(">>>>> Start Copying Files: ") + CString(FILESADDED_DB_PATH));
	OutputDebugString(_T("\n>>>>> Start Copying Files: ") + CString(FILESADDED_DB_PATH));

	if ( objFileNameDB.GetFirst () != NULL )
	{
		CString csTempFileName;
		CString csExePathNameExecute;
		LPTSTR lpDBValue = NULL;
		DWORD dwTypeOfCall = 0;

		LPVOID lpVoid = objFileNameDB.GetFirst();
		while(lpVoid)
		{
			lpDBValue = NULL;
			objFileNameDB.GetKey(lpVoid, lpDBValue);
			
			csTempFileName = lpDBValue;

			if(((csTempFileName.Find(csInputFolderName.MakeLower())!= -1)
				&&(csTempFileName.Find(_T("BinaryCollection"))!= -1))
				|| ((csTempFileName.Find(csInputFolderName.MakeLower())!= -1)
				&&(csTempFileName.Find(_T("input"))!= -1)))

			{
				g_objLogApp.AddLog1(_T(">>>>> Ignoring File: ") + csTempFileName);
				OutputDebugString(_T("\n>>>>> Ignoring File: ") + csTempFileName);
				lpVoid = objFileNameDB.GetNext(lpVoid);
				continue;
			}
			if(PathFileExists(csTempFileName))
			{
				CString csFolder,csFileName,csPath;
				csFileName = BINARY_COLLECTION_PATH;
				int iFind = csTempFileName.ReverseFind('\\');
				if(iFind != -1)
				{
					csPath  = csTempFileName.Right(csTempFileName.GetLength() - iFind);		
					csFileName+=csTempFileName.Mid(2,iFind-2);
					CreateAllDirectory (csFileName);
					csFileName = REGSHOT_FOLDER_PATH+ csFileName + csPath;	
					csFileName.MakeLower();
				}
				g_objLogApp.AddLog1(_T(">>>>> Copy File: ") + csTempFileName + _T(" - ") + csFileName);
				OutputDebugString(_T("\n>>>>> Copy File: ") + csTempFileName + _T(" - ") + csFileName);
				CopyFile(csTempFileName, csFileName, true);
			}
			else
			{
				g_objLogApp.AddLog1(_T(">>>>> Failed To Copy: ") + csTempFileName);
				OutputDebugString(_T("\n>>>>> Failed To Copy: ") + csTempFileName);
			}
			bFoundNewFiles = true;
			lpVoid = objFileNameDB.GetNext(lpVoid);
		}
	}
	objFileNameDB.RemoveAll();
	CompressFolder(BINARY_COLLECTION_FULLPATH,BINARY_COLLECTION_ZIP_PATH,false,false);
	/*TCHAR csPATH[MAX_PATH] = {0};
	_tcscpy_s(csPATH, MAX_PATH, _T("C:\\Test\\"));
	UnzipToFolder(BINARY_COLLECTION_ZIP_PATH, csPATH, _T("virus007"), false);*/
	return bFoundNewFiles;		
}

void CGeneralServices::CreateAllDirectory(CString csFolderName)
{
	int curPos = 0;
	CString csFolder;
	CString resToken = csFolderName.Tokenize(_T("\\"), curPos);
	csFolder = REGSHOT_FOLDER_PATH + resToken;
	while(resToken != _T(""))
	{
#pragma warning (disable: 6031)
		_tmkdir(csFolder);
#pragma warning (default: 6031)
		resToken= csFolderName.Tokenize(_T("\\"), curPos);
		csFolder += _T("\\") + resToken;
	}
}
