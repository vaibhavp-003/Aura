/*======================================================================================
   FILE				: WinWebSecurityWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinWebSecurityWorm
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
   CREATION DATE	: 12/15/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.61
					Resource : Shweta
					Description: created this class to fix CWinWebSecurityWorm 2009

					version : 2.5.0.63
					Resource : Shweta
					Description: Added code for new varient SystemSecurity

					version : 2.5.0.71
					Resource : Anand
					Description: Added code for new variant SystemSecurity by .lnk files

					version : 2.5.0.78
					Resource : Shweta Mulay
					Description: Added code SystemSecurity files version tab chek and the registry key
					
					version : 2.5.0.80
					Resource : Shweta Mulay
					Description: Added code SystemSecurity new varient

					Version	: 2.5.1.01
					Resource : Siddharth
					Description: Added code fcn resan issue. Application Data random exe

					Version	: 2.5.1.08
					Resource : Shweta Mulay
					Description: Added code for Smart virus Eliminator.

					Version	: 2.5.1.08
					Resource : Shweta Mulay
					Description: Added code for system defender.
					
					Version	: 2.5.1.14
					Resource : Shweta Mulay
					Description: Handled Enterprise Suit
					
					Version	: 2.5.1.15
					Resource : Shweta Mulay
					Description: Handled Additional Guard 

========================================================================================*/

#include "pch.h"
#include "WinWebSecurityWorm.h"
#include "PathExpander.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove WinWebSecurityWorm
	Author			: Shweta M
	Description		: This function checks for random folder in AppPath for WinWebSecurityWorm 2009
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		CString csData ;
		CString csFolderName,csFolder ;
		CString csPath;
		int iPos = 0 ;
		TCHAR szPath [ MAX_PATH ] = { 0 } ;
		CStringArray csArrLocations ;
		bool bSpywareFound = false ;

		csArrLocations.Add(RUN_REG_PATH);
		if(m_bScanOtherLocations)
			csArrLocations.Add(CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH));

		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		for ( int iLocCnt =0; iLocCnt < csArrLocations.GetCount() ; iLocCnt++ )
		{
			//Enumerate run Entries
            
            vector<REG_VALUE_DATA> vecRegValues;
	        m_objReg.EnumValues(csArrLocations.GetAt ( iLocCnt ) , vecRegValues, HKEY_LOCAL_MACHINE);
			
			for ( size_t ivalcnt = 0 ; ivalcnt < vecRegValues.size() ; ivalcnt++ )
			{
				if(IsStopScanningSignaled())
					return ( false ) ;
				
                /*if ( !CheckValueToBeDigit ( vecRegValues [ivalcnt].strValue ) )
					continue;*/

				bSpywareFound = false ;
				csData.Format(_T("%s") , (TCHAR*)vecRegValues [ivalcnt].bData);
				csData.MakeLower();

				iPos = csData .ReverseFind ( _T('\\') );
				if ( iPos <= 0 )
					continue ;
				csFolderName = csData .Left ( iPos ) ;
				csFolder = csFolderName ;

				iPos = csFolderName .ReverseFind ( _T('\\') ) ;
				if ( iPos <= 0 )
					continue ;
				csFolderName = csFolderName.Right ( csFolderName.GetLength() - (iPos + 1) ) ;

				CString csValue ;
				csValue.Format (_T("%s") ,(TCHAR*)vecRegValues [ivalcnt].strValue ) ;
				csValue.MakeLower();
				if ( csValue == "windows enterprise defender" || csValue == "system defender" || csValue == "enterprise suite")
				{
					csFolder.Replace(_T("\""),BLANKSTRING );
					RemoveFolders ( csFolder , 12342 , false );
					SendScanStatusToUI ( Special_RegVal , 12342 , HKEY_LOCAL_MACHINE,  
						 csArrLocations.GetAt(iLocCnt) , vecRegValues [ivalcnt].strValue,
						 vecRegValues [ivalcnt].Type_Of_Data,vecRegValues [ivalcnt].bData,
						 vecRegValues [ivalcnt].iSizeOfData) ;
						continue;
				}
				
				if ( ! CheckValueToBeDigit ( csFolderName , false ) )
					continue ;

				//If Appdata path found go to folder
				SHGetFolderPath ( 0 , CSIDL_COMMON_APPDATA , 0 , 0 , szPath ) ;
				if ( 0 != szPath [ 0 ] )
				{
					csPath = szPath ;
					csPath.MakeLower();
					if ( csData.Find ( csPath ) == -1 )
							continue;
				}

				if ( CheckSpyFolder ( csData , csPath , csFolderName , bToDelete ) )
				{
					bSpywareFound = true ;
				}
				else if ( CheckIfSpywarePath ( csData  , bToDelete ) ) //Check for 3 things Single Folder, 1 exe and 2 other files. Check for strings in the files
				{
					if ( CheckVersionTab ( csData ) )
					{						
						bSpywareFound = true ;
					}
				}

				if ( bSpywareFound )
				{
					m_bSplSpyFound = true ;
					SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_LOCAL_MACHINE,  
										 csArrLocations.GetAt(iLocCnt) , vecRegValues [ivalcnt].strValue,
										 vecRegValues [ivalcnt].Type_Of_Data,vecRegValues [ivalcnt].bData,
										 vecRegValues [ivalcnt].iSizeOfData) ;
				}
			}
		}

		//version : 2.5.0.71
		//Resource : Anand
        if ( !IsStopScanningSignaled() && CheckByStartProgramsLink() )
		{
            m_bSplSpyFound = true ;
		}

		if ( false == m_bSplSpyFound && !IsStopScanningSignaled())
		{
			CheckAppFolder();
		}

		if(!bToDelete && !IsStopScanningSignaled())
		{
			CheckForXPHomeSecurity();
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CXPProWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckValuetobeDigit
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: check if the value is only digits
	Author			: Shwetam
	Description		: checks the string for all digits or at least one digit characters
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm::CheckValueToBeDigit ( const CString & csVal  , bool bAllDigits )
{
	bool bAllCharsAreDigits = true ;
	bool bAtleastOneCharIsDigit = false ;

	for ( int i = 0 , iTotal = csVal . GetLength() ; i < iTotal ; i++ )
	{
		if ( isdigit ( csVal [ i ] ) )
			bAtleastOneCharIsDigit = true ;
		else
			bAllCharsAreDigits = false ;
	}

	if ( bAllDigits )
	{
		return ( bAllCharsAreDigits ) ;
	}
	else
	{
		return ( bAtleastOneCharIsDigit ) ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfSpywarePath
	In Parameters	: CString, bool
	Out Parameters	: bool
	Purpose			: check and report radom App Path Folder
	Author			: Shwetam
	Description		: checks if the files has strings and if file exists
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm::CheckIfSpywarePath ( CString csPath , bool bToDelete)
{
	//Application Data\522382060\1358331447.exe
	CString csFile , csFolder ;

	csPath.Replace( _T("\""),_T("") );
	if ( _taccess ( csPath , 0 ) != 0 )
		return false;

	csFile = csPath.Right ( csPath.GetLength() - csPath.ReverseFind('\\') -1 );
	csFolder = csPath.Left ( csPath.ReverseFind ( '\\' )) ;

	CArray<CStringA,CStringA> csArr , csArr1, csArr2;
	csArr.Add ( "WinwebSecurity.exe" );
	csArr.Add ( "WinwebSecurity" );
	csArr.Add ( "securedownloaddirect.com" );
	
	//2.5.0.63
	csArr1.Add ( "You may scan your PC to locate malware/spyware threats");
	csArr1.Add ( "SystemSecurity");

	csArr2.Add ( "greatmarketingservices.com");

	//Seach for String WinwebSecurity.exe
	if ( false == SearchStringsInFile ( csPath , csArr ) )
	{	//2.5.0.63
		if ( false == SearchStringsInFile ( csPath , csArr1 ) )
		{
			if ( false == SearchStringsInFile ( csPath , csArr2 ) )
			return ( false );
	}
	}

	if ( m_objEnumProcess.IsProcessRunning ( csPath , bToDelete ) )
	{
        SendScanStatusToUI ( Special_Process, m_ulSpyName , csPath  ); 
	}

	SendScanStatusToUI ( Special_File , m_ulSpyName , csPath  );
	RemoveFolders ( csFolder , m_ulSpyName , bToDelete );
	
	return true ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckFolderForPattern
	In Parameters	: LPCTSTR , LPCTSTR
	Out Parameters	: bool
	Purpose			: check if the pattern present in folder
	Author			: Anand
	Description		: check if the pattern present in folder
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm :: CheckFolderForPattern ( LPCTSTR szPath , LPCTSTR szPattern )
{
    HANDLE hSearch = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA Data = { 0 } ;
    TCHAR szSearchPath [ MAX_PATH ] = { 0 } ;

    if ( ( _tcslen ( szPath ) + _tcslen ( szPattern ) + 2 ) >= _countof ( szSearchPath ) )
        return ( false ) ;

    _tcscpy_s ( szSearchPath , szPath ) ;
    _tcscat_s ( szSearchPath , _T("\\") ) ;
    _tcscat_s ( szSearchPath , szPattern ) ;

    hSearch = FindFirstFile ( szSearchPath , &Data ) ;
    if ( hSearch == INVALID_HANDLE_VALUE )
        return ( false ) ;

    FindClose ( hSearch ) ;
    return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ResolveShortcut
	In Parameters	: LPCTSTR , LPTSTR , DWORD
	Out Parameters	: bool
	Purpose			: resolves the target filename from lnk file
	Author			: Anand
	Description		: resolves the target filename from lnk file
    Net Link        : http://www.codeproject.com/KB/shell/create_shortcut.aspx
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm :: ResolveShortcut ( LPCTSTR szShortcutFileName , LPTSTR szTargetFileName , DWORD cbTargetFileName )
{
    HRESULT hRes = E_FAIL;
    CComPtr<IShellLink> ipShellLink = NULL ;
    TCHAR szPath [ MAX_PATH ] = { 0 } ;
    TCHAR szDesc [ MAX_PATH ] = { 0 } ;
    WIN32_FIND_DATA wfd = { 0 } ;
    WCHAR wszTemp [ MAX_PATH ] = { 0 } ;

	// Removed Coinit as this is already done in AuScanner
	//HRESULT hr = CoInitialize(NULL);
	//COINITIALIZE_OUTPUTDEBUGSTRING(hr);

	// Get a pointer to the IShellLink interface
	hRes = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&ipShellLink);
	COCREATE_OUTPUTDEBUGSTRING(hRes);
	if(FAILED(hRes))
	{
		//CoUninitialize() ;
		return ( false ) ;
	}

    // Get a pointer to the IPersistFile interface
    CComQIPtr<IPersistFile> ipPersistFile ( ipShellLink ) ;

    // IMP: IPersistFile is using LPCOLESTR, so make sure that the string is Unicode
    // Open the shortcut file and initialize it from its contents
    hRes = ipPersistFile -> Load ( szShortcutFileName , STGM_READ ) ;
    if ( FAILED ( hRes ) )
    {
        //CoUninitialize() ;
        return ( false ) ;
    }

    /*
    INFO: This was commented because if the file was moved or renamed a mesage window appears
          which needs a user response. This mesage windows hangs the special spyware scanning
          as the message box has come from service and is not viewable to the user.
    // Try to find the target of a shortcut, even if it has been moved or renamed
    hRes = ipShellLink -> Resolve ( NULL , SLR_UPDATE ) ;
    if ( FAILED ( hRes ) ) 
    {
        CoUninitialize() ;
        return ( false ) ;
    }
    */

    // Get the path to the shortcut target
    hRes = ipShellLink -> GetPath ( szTargetFileName , cbTargetFileName , &wfd , SLGP_RAWPATH ) ;
    if ( FAILED ( hRes ) )
    {
        //CoUninitialize() ;
        return ( false ) ;
    }

    //CoUninitialize() ;
    return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckByStartProgramsLink
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: checks if link present and reports folder
	Author			: Anand
	Description		: checks if link present and the reports the folder where the target lies
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm :: CheckByStartProgramsLink()
{
    CString csRegValue , csRegData ;
    CPathExpander objPathExpander ;
    bool bSpywarePresent = false ;
    TCHAR szLinkTargetFileName [ MAX_PATH ] = { 0 } ;
    TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;
    TCHAR szStartProgramsPath [ MAX_PATH ] = { 0 } ;
    TCHAR* pSlashPtr = NULL ;
    TCHAR* szLinkFileName[] =
    {
        _T("System Security\\System Security.lnk") ,
		_T("System Security\\System Security 2009.lnk") ,
        NULL
    } ;

    if ( ( _tcslen ( objPathExpander . m_CUPROFILE ) + _tcslen ( _T("\\Start Menu\\Programs") ) + 1  >= _countof ( szStartProgramsPath ) ) )
        return ( false ) ;

    _tcscpy_s ( szStartProgramsPath , objPathExpander . m_CUPROFILE ) ;
    _tcscat_s ( szStartProgramsPath , _T("\\Start Menu\\Programs") ) ;

    if ( _taccess ( szStartProgramsPath , 0 ) )
        return ( bSpywarePresent ) ;

    for ( short i = 0 ; szLinkFileName [ i ] ; i++ )
    {
        if ( _tcslen ( szStartProgramsPath ) + _tcslen ( szLinkFileName [ i ] ) + 2 >= _countof ( szFullFileName ) )
            continue ;

        memset ( szFullFileName , 0 , sizeof ( szFullFileName ) ) ;
        _tcscpy_s ( szFullFileName , szStartProgramsPath ) ;
        _tcscat_s ( szFullFileName , _T("\\") ) ;
        _tcscat_s ( szFullFileName , szLinkFileName [ i ] ) ;

        if ( _taccess ( szFullFileName , 0 ) )
            continue ;

        if ( !ResolveShortcut ( szFullFileName , szLinkTargetFileName , _countof ( szLinkTargetFileName ) ) )
            continue ;

        pSlashPtr = _tcsrchr ( szLinkTargetFileName , _T('\\') ) ;
        if ( NULL == pSlashPtr )
            continue ;

        *pSlashPtr = 0 ;

        if ( !CheckFolderForPattern ( szLinkTargetFileName , _T("*.exe") ) )
            continue ;

        //if ( !CheckFolderForPattern ( szLinkTargetFileName , _T("*.udb") ) )
        //	continue ;

        *pSlashPtr = _T('\\') ;
        SearchStringInRunKeyData ( m_ulSpyName , szLinkTargetFileName , csRegValue , csRegData , HKEY_LOCAL_MACHINE ) ;

        *pSlashPtr = 0 ;
        RemoveFolders ( szLinkTargetFileName , m_ulSpyName , false ) ;
        bSpywarePresent = true ;

	// report the link file and folder also
        pSlashPtr = _tcsrchr ( szFullFileName , _T('\\') ) ;
        if ( NULL == pSlashPtr )
            continue ;

        *pSlashPtr = 0 ;
		RemoveFolders ( szFullFileName , m_ulSpyName , false ) ;
    }

    return ( bSpywarePresent ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckCmpyTab
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: checks if VersionTab Present
	Author			: Shweta Mulay
	Description		: checks if Version tab present and the reports the folder & the registry
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm :: CheckVersionTab ( CString csPath , bool bFolder )
{
	CFileVersionInfo objFV;
	bool bVTabNotFound = false ;
	CString csFile , csFolder ;
	CString csLowerCasePath(csPath);

	csLowerCasePath.MakeLower();
	if(-1 != csLowerCasePath.Find(_T("ezpinst.exe")))
	{
		return false;
	}

	csPath.Replace( _T("\""),_T("") );
	if ( _taccess ( csPath , 0 ) != 0 )
		return false;

	csFile = csPath.Right ( csPath.GetLength() - csPath.ReverseFind('\\') -1 );
	csFolder = csPath.Left ( csPath.ReverseFind ( '\\' )) ;
	bVTabNotFound = objFV . DoTheVersionJob ( csPath , false ) ;
	
	if ( false == bVTabNotFound )
	{
		TCHAR csCmpy[MAX_PATH] = { 0 } ;
		TCHAR csOriginal[MAX_PATH] = { 0 } ;
		if ( objFV.GetCompanyName ( csPath , csCmpy ) )
		{
			if ( _tcscmp ( csCmpy , _T("") ) == 0 || 
				 _tcscmp ( csCmpy , _T ( "System Sec." ) ) == 0 || 
				 _tcscmp ( csCmpy , _T ( "System Security" ) ) == 0 )

			{
				bVTabNotFound = true ;
			}
			else if ( _tcscmp ( csCmpy , _T( "Microsoft Corporation" ) ) == 0 ) 
			{
				if ( CheckIfSpywarePath ( csPath , false) )
				{
					bVTabNotFound = true ;
				}
				else
				{
					 objFV . GetFileInternalName ( csPath , csOriginal ) ;
					 if ( _tcscmp ( csOriginal , L"MSNTR.EXE" ) == 0 )
						bVTabNotFound = true ;
				}
			}
		}
	}

	if ( bVTabNotFound )
	{
		SendScanStatusToUI ( Special_File , m_ulSpyName , csPath );
		if ( bFolder )
		RemoveFolders ( csFolder , m_ulSpyName , false );

		//Chk for registry
		//Get the registry entry only

		// caught false positive in case trojan copies its file in all locations with folder name. e.g. APPDATA\Microsoft.exe
		//csFile = csFile.Left ( csFile.ReverseFind('.') ) ;
		//if ( m_objReg.KeyExists ( (CString)SOFTWARE + (CString)BACK_SLASH + csFile , HKEY_LOCAL_MACHINE ) )
		//	EnumKeynSubKey ( HKLM + (CString)BACK_SLASH + (CString)SOFTWARE + (CString)BACK_SLASH + csFile , m_ulSpyName ) ;
	}

	return bVTabNotFound ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAppFolder
	In Parameters	: 
	Out Parameters	: void
	Purpose			: checks if Application Data folder has infection
	Author			: Shweta Mulay
	Description		: checks if Application Data has infection and 
	Version			: 2.5.0.80
--------------------------------------------------------------------------------------*/
void CWinWebSecurityWorm::CheckAppFolder(void)
{
	CString csCheckPath;
	CString csFileName;
	CString csAppDataPath;	
	CStringArray csArrSpyLocation;
	CStringArray csArrFilnm;
	CStringArray csArrData;
	
	CFileFind objFileFind;
	
	BOOL bFoundFile = FALSE ;
	
	CFileVersionInfo objVer;
	CEnumProcess objEnumProcess;
	CPathExpander objPathExpander;

	TCHAR szPath [ MAX_PATH ] = { 0 } ;

	if(IsStopScanningSignaled())
	{
		return;
	}

	//2.5.1.01 //Siddharth
	//All user info local setting application data
	LoadAvailableUsers ();
	if(IsStopScanningSignaled())
	{
		return;
	}

	SHGetFolderPath ( 0, CSIDL_LOCAL_APPDATA ,0 , 0, szPath );// get user local setting application data path
	CString csTempPath(szPath);
	LPVOID posUserName = m_objAvailableUsers.GetFirst();
	while ( posUserName )
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		LPTSTR strUserName = NULL;
		m_objAvailableUsers.GetData(posUserName, strUserName);
		csTempPath.MakeLower ();
		CString csTemp(strUserName);
		if( csTempPath.Find(csTemp) != -1 )
		{
			csTempPath.Replace(csTemp , _T("") ) ;
			break;
		}
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}

	if(IsStopScanningSignaled())
	{
		return;
	}

	posUserName = m_objAvailableUsers.GetFirst();
	while(posUserName)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		LPTSTR strUserName = NULL;
		m_objAvailableUsers.GetData(posUserName, strUserName);
		CString csTemp(strUserName);
		csTemp = csTemp + csTempPath;
		csArrSpyLocation.Add (csTemp);
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}

	if(IsStopScanningSignaled())
	{
		return;
	}

	//SHGetFolderPath ( 0, CSIDL_COMMON_APPDATA ,0 , 0, szPath );// get all user application data path
	//csArrSpyLocation . Add ( szPath );
	SHGetFolderPath ( 0, CSIDL_APPDATA ,0 , 0, szPath );// get user application data path
	
	//2.5.1.07 //vaibhav
	LPTSTR strUserName = NULL ;
	CString csTmpPath(szPath) ;
	csTmpPath . MakeLower() ;

	posUserName = m_objAvailableUsers.GetFirst();	
	while ( posUserName )
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		strUserName = NULL ;
		m_objAvailableUsers . GetData ( posUserName , strUserName ) ;
		if ( csTmpPath . Find ( strUserName ) != -1 )
		{
			csTmpPath . Replace ( strUserName , _T("") ) ;
			break ;
		}

		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}

	if(IsStopScanningSignaled())
	{
		return;
	}

	posUserName = m_objAvailableUsers.GetFirst();	
	while(posUserName)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		strUserName = NULL ;
		m_objAvailableUsers.GetData(posUserName, strUserName);
		CString csTemp(strUserName);
		csTemp = csTemp + csTmpPath;
		csArrSpyLocation.Add (csTemp);
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}

	if(IsStopScanningSignaled())
	{
		return;
	}

	for ( int iLocCnt = 0 ; static_cast < int > ( iLocCnt < csArrSpyLocation.GetCount( ) ) ; iLocCnt++ )
	{
		bFoundFile = FALSE;

		if(IsStopScanningSignaled())
		{
			break;
		}

		bFoundFile = objFileFind.FindFile ( csArrSpyLocation.GetAt ( iLocCnt ) +  _T("\\*.*" ) ) ;
		
		if ( FALSE == bFoundFile )
			continue;

		while ( bFoundFile )
		{
			if(IsStopScanningSignaled())
				break ;

			bFoundFile = objFileFind.FindNextFile();

			if ( objFileFind.IsDots() ) 
				continue ;
			
			csCheckPath = objFileFind.GetFilePath();
			csFileName = objFileFind .GetFileName ();
			if ( objFileFind.IsDirectory() ) 
			{
				if ( false == CheckValueToBeDigit ( objFileFind.GetFileName() ) )
				{
					CheckOtherFakeInfection ( objFileFind.GetFileName() , objFileFind.GetFilePath()) ;
					CheckForEnterpriseSuit ( objFileFind.GetFileName() , objFileFind.GetFilePath() );
					CheckForSysguardinfection ( objFileFind.GetFileName() , objFileFind.GetFilePath() );
					continue ;
				}

				if ( CheckVersionTab ( csCheckPath + _T("\\") + objFileFind.GetFileName() + _T(".exe") ) )
				{
					RemoveFolders ( csCheckPath , m_ulSpyName , false ); 
				}
				else if ( CheckVersionTab ( csCheckPath + _T("\\_") + objFileFind.GetFileName() + _T(".exe") ) )
				{
					RemoveFolders ( csCheckPath , m_ulSpyName , false ); 
				}
			}

			if (false == objFileFind.IsDirectory() && ( csCheckPath.Find (_T(".exe")) != -1 ) ) 
			{
				if ( CheckVersionTab ( csCheckPath , false) )
				{
					if ( objEnumProcess.IsProcessRunning ( csCheckPath , false ) )
						SendScanStatusToUI ( Special_Process , m_ulSpyName , csCheckPath ) ;
				}
				
				CheckForRunEntry(csFileName,csCheckPath);
			}

		}
		objFileFind . Close() ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForRunEntry
	In Parameters	: 
	Out Parameters	: void
	Purpose			: checks if spyware made any Run Entry in the Registry
	Author			: Siddharth
	Description		: checks for Spyware remians in app, run and uninstall path entry
	Version			: 2.5.1.01
--------------------------------------------------------------------------------------*/
void CWinWebSecurityWorm::CheckForRunEntry(CString csFileName, CString csCheckPath)
{
	CEnumProcess objEnumProcess;
	CExecuteProcess objExecProc;
	CString csMainKey;
	CString csData;
	CString csSid;
	CString csKey;
	CString csDatFileName (csCheckPath);

	csSid = objExecProc.GetCurrentUserSid();
	csSid = csSid + _T("\\") + RUN_REG_PATH;
	csKey = UNINSTALL_PATH;

	csFileName.Replace (_T(".exe"),_T(""));
	if ( !m_objReg.Get(csSid , csFileName , csData , HKEY_USERS ) )
		return ;

	csData.MakeLower ();
	if ( csData.Find (csCheckPath)== -1 )
		return ;
	
	if ( objEnumProcess.IsProcessRunning ( csCheckPath , false ) )
		SendScanStatusToUI ( Special_Process , m_ulSpyName , csCheckPath ) ;
	
	SendScanStatusToUI ( Special_File , m_ulSpyName , csCheckPath ) ;
	SendScanStatusToUI ( Special_RegVal , m_ulSpyName ,HKEY_USERS,csSid ,csFileName,REG_SZ,(LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
	
	csKey = csKey + _T("\\") + csFileName ;
	if ( m_objReg.KeyExists ( csKey , HKEY_LOCAL_MACHINE ) )
	{
		EnumKeynSubKey ( CString ( _T("HKEY_LOCAL_MACHINE\\" ) ) + csKey , m_ulSpyName ) ;
	}
		
	csDatFileName . Replace ( _T( ".exe" ) , _T ( ".dat" ) ) ;
	if ( PathFileExists ( csDatFileName ) )
	{
		SendScanStatusToUI ( Special_File , m_ulSpyName , csDatFileName ) ;
	}

	csDatFileName . Replace ( _T( ".dat" ) , _T( "_nav.dat" ) ) ;
	if ( PathFileExists ( csDatFileName ) )
	{
		SendScanStatusToUI ( Special_File , m_ulSpyName , csDatFileName ) ;
	}

	csDatFileName.Replace ( _T( "_nav.dat" ),_T( "_navps.dat" ) ) ;
	if ( PathFileExists ( csDatFileName ) )
	{
		SendScanStatusToUI ( Special_File , m_ulSpyName , csDatFileName ) ;
	}

	return ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckOtherFakeInfection
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: checks and report other fake antispyware entry found
	Author			: Shweta M
	Description		: checks for other fake AntiSpyware entry
	Version			: 2.5.1.08
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm:: CheckOtherFakeInfection ( const CString& csFolderName , const CString& csFullFolderPath)
{
	CString csVal ,csFilename ;
	bool bAlphanum = false ,bexeFound = false,bicoFound =false;
	BOOL bFileFound = FALSE;
	CFileFind objFF;
	CFileVersionInfo objFV;
	TCHAR csCmpy[MAX_PATH] = { 0 } ;

	for ( int i = 0 ; i< csFolderName .GetLength () ; i++ )
	{
		if ( isdigit ( csFolderName [ i ] ) )
			bAlphanum = true ;

		if(IsStopScanningSignaled())
			return ( false ) ;
	}

	if ( !bAlphanum )
		return ( false ) ;
	
	bFileFound  = objFF.FindFile(csFullFolderPath + BACK_SLASH + _T("SM*.*"));

	while( bFileFound )
	{
		if(IsStopScanningSignaled())
			break ;

		bFileFound = objFF.FindNextFile();
		csFilename = objFF.GetFileName();
		csFilename.MakeLower();

		if ( csFilename.Find ( _T ( ".exe" ) ) > 0 )
		{
			if ( objFV.DoTheVersionJob ( csFullFolderPath , false ) )
			{
				bexeFound = true;	
			}
			else
			{
				if (! objFV.GetCompanyName ( csFullFolderPath , csCmpy ) )
					continue ;
			
				if (_tcscmp ( csCmpy , L"" ) == 0 ) 
				{
					bexeFound = true;	
				}
			}
		}

		if ( ( csFilename.Find ( _T ( ".ico" ) ) > 0 ) || objFF.IsDirectory() )
			bicoFound = true;
	}

	objFF.Close();

	if ( bexeFound && bicoFound )
	{
		RemoveFolders ( csFullFolderPath , 12055 , false ) ;
	}

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSpyFolder
	In Parameters	: const CString, const CString, const CString , bool
	Out Parameters	: bool
	Purpose			: checks Spyware folder
	Author			: vaibhav Desai
	Description		: Checks Spyware folder
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm :: CheckSpyFolder ( const CString csFileFullPath , const CString csAppPath , const CString csFolderName , bool bToDelete )
{
	CString csFileName ;
	CString csFolderPath ;
	CFileVersionInfo objFileVersion ;
	CArray<CStringA,CStringA> csArr ;
	CString csFilePath = csFileFullPath ;
	int iPos = 0;
	
	csArr.Add ( "security" );
	csArr.Add ( "microsoft" );
	csArr.Add ( "false" );

	iPos = csFilePath.Find( _T(".exe") );
	if ( iPos <= 0)
	{
		return ( false ) ;
	}

	csFilePath = csFilePath .Left( iPos + 4 );

	csFilePath.Replace( _T("\"") , _T("") );

	if ( _taccess ( csFilePath , 0 ) != 0 )
		return ( false ) ;
	
	csFileName = _T("wp") ;
	csFileName = csFileName + csFolderName.Left ( 4 ) + _T(".exe") ;
	
	if( csFilePath.Find( csFileName ) <= 0 )
		return ( false ) ;
	
	if ( !objFileVersion.DoTheVersionJob ( csFilePath , bToDelete ) )
		return ( false ) ;

	if ( !SearchStringsInFile ( csFilePath , csArr ) )
	{
		return ( false ) ;
	}
	
	csFolderPath = csAppPath + _T("\\") + csFolderName ;

	if ( m_objEnumProcess.IsProcessRunning ( csFilePath , bToDelete ) )
	{
        SendScanStatusToUI ( Special_Process, m_ulSpyName , csFilePath  ); 
	}

	SendScanStatusToUI ( Special_File , m_ulSpyName , csFilePath  );
	RemoveFolders ( csFolderPath  , m_ulSpyName , bToDelete );
	
	return true ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForEnterpriseSuit
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove Additional Guard 
	Author			: Shweta M
	Description		: This function checks for random folder in AppPath for EnterpriseSuit and Additional Guard 
--------------------------------------------------------------------------------------*/
bool  CWinWebSecurityWorm::CheckForEnterpriseSuit ( const CString& csFolderName , const CString& csFullFolderPath)
{
	CString csFolderchar;

	csFolderchar = csFolderName.Left(4) ;
	if ( _taccess( csFullFolderPath + _T("\\WE") + csFolderchar + _T(".exe") , 0 ) == 0 ) 
	{
		m_bSplSpyFound = true;
		RemoveFolders ( csFullFolderPath , 14255 , false );
	}
	else if ( _taccess( csFullFolderPath + _T("\\WI") + csFolderchar + _T(".exe") , 0 ) == 0 ) 
	{
		m_bSplSpyFound = true;
		RemoveFolders ( csFullFolderPath , 20901 , false );
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForSysguardinfection
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove SysGuard 
	Author			: Shweta M
	Description		: This function checks for random folder in AppPath for SysGuard 
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm:: CheckForSysguardinfection ( const CString& csFolderName , const CString& csFullFolderPath)
{
	CFileFind objFF;
	BOOL bFound = FALSE ;
	bool bInfected = false ;
	bFound =objFF.FindFile (csFullFolderPath + _T("\\*.*"));
	int cnt = 0;
	CString csFile;
	CFileVersionInfo objFVersionInfo;

	while (bFound )
	{
		bFound = objFF.FindNextFileW();

		if (objFF.IsDots())
			continue;

		if (objFF.IsDirectory())
			continue;

		cnt++ ;
		csFile = objFF.GetFilePath();

		csFile.MakeLower();
		if ( csFile.Find(_T("sysguard.exe"),0) == -1 )
			continue ;

		if ( objFVersionInfo .DoTheVersionJob(csFile , false ) )
			bInfected = true ;
	}
	objFF.Close();
	if ( bInfected  && cnt == 1 )
	{
		RemoveFolders(csFullFolderPath , 8664 , false);
		return true ;
	}
	else
		return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForXPHomeSecurity
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Check and remove XPHomeSecurity
	Author			: Anand Srivastava
	Description		: This function checks for random folder in AppPath for SysGuard 
--------------------------------------------------------------------------------------*/
bool CWinWebSecurityWorm::CheckForXPHomeSecurity()
{
	bool bInfectionFound = false;
	BOOL bWorking = FALSE;
	CFileFind finder;
	CString csData, csHoldPath, csKey;
	TCHAR szAppDataPath[MAX_PATH] = {0};

	if(IsStopScanningSignaled())
	{
		return false;
	}

	MakeListofLocations();
	for(INT_PTR i = 0, iTotal = m_csArrRegistryKeys.GetCount(); i < iTotal; i++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		csData = _T("");
		csKey = m_csArrRegistryKeys.GetAt(i) + _T("\\software\\classes\\exefile\\shell\\open\\command");
		m_objReg.Get(csKey, _T(""), csData, HKEY_USERS);
		csData.MakeLower();
		if(_T("") == csData)
		{
			continue;
		}

		for(INT_PTR j = 0, jTotal = m_csArrSpyLocation.GetCount(); j < jTotal; j++)
		{
			if(IsStopScanningSignaled())
			{
				break;
			}

			csHoldPath.Format(_T("%s\\*"), m_csArrSpyLocation.GetAt(j));
			bWorking = finder.FindFile(csHoldPath);
			if(!bWorking)
			{
				continue;
			}

			while(bWorking)
			{
				if(IsStopScanningSignaled())
				{
					break;
				}

				bWorking = finder.FindNextFile();
				if(finder.IsDirectory())
				{
					continue;
				}

				csHoldPath = finder.GetFilePath();
				csHoldPath.MakeLower();

				if(_tcsstr(csData, csHoldPath))
				{
					if(m_objEnumProcess.IsProcessRunning(csHoldPath, false))
					{
						SendScanStatusToUI(Special_Process, m_ulSpyName, csHoldPath);
					}

					SendScanStatusToUI(Special_File, m_ulSpyName, csHoldPath);
					bInfectionFound = true;
				}
			}

			finder.Close();
		}
	}

	return bInfectionFound;
}

/*-------------------------------------------------------------------------------------
	Function		: MakeListofLocations
	In Parameters	: 
	Out Parameters	: 
	Purpose			: make local settingss \ app data paths for all users
	Author			: Anand Srivastava
	Description		: make local settingss \ app data paths for all users
--------------------------------------------------------------------------------------*/
void CWinWebSecurityWorm::MakeListofLocations()
{
	TCHAR szPath [ MAX_PATH ] = { 0 } ;
	LPTSTR strUserName = NULL ;	
	LPVOID posUserName ;
	CString csFilePath ;

	LoadAvailableUsers();
	SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, szPath); // get user local setting application data path
	CString csLocalAppPath(szPath);
	csLocalAppPath.MakeLower();

	posUserName = m_objAvailableUsers.GetFirst () ;
	while ( posUserName )
	{
		strUserName = NULL ;
		m_objAvailableUsers . GetData ( posUserName , strUserName ) ;
		if ( csLocalAppPath . Find ( strUserName ) != -1 )
		{
			csLocalAppPath . Replace ( strUserName , _T("") ) ;
			break ;
		}

		posUserName = m_objAvailableUsers . GetNext ( posUserName ) ;
	}

	SHGetFolderPath ( 0 , CSIDL_APPDATA , 0 , 0, szPath ) ; // get user application data path
	CString csAppPath ( szPath );
	csAppPath . MakeLower() ;

	posUserName = m_objAvailableUsers.GetFirst () ;
	while ( posUserName )
	{
		strUserName = NULL ;
		m_objAvailableUsers . GetData ( posUserName , strUserName ) ;
		if ( csAppPath . Find ( strUserName ) != -1 )
		{
			csAppPath . Replace ( strUserName , _T("") ) ;
			break ;
		}

		posUserName = m_objAvailableUsers . GetNext ( posUserName ) ;
	}

	posUserName = m_objAvailableUsers.GetFirst () ;	
	while(posUserName)
	{
		strUserName = NULL ;
		m_objAvailableUsers.GetData ( posUserName , strUserName ) ;
		CString csUserPath ( strUserName ) ;		
		m_csArrSpyLocation . Add ( csUserPath + csLocalAppPath ) ;
		posUserName = m_objAvailableUsers . GetNext ( posUserName ) ;
	}

	CRegistry objRegistry;
	CString csMainKey(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
	objRegistry.EnumSubKeys(csMainKey, m_csArrRegistryKeys, HKEY_LOCAL_MACHINE);
}
