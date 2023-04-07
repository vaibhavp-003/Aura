/*=============================================================================
   FILE				: ShellExecWormList.cpp
   ABSTRACT			: Class for generic scanning of files based on heuristic factors
   DOCUMENTS		: 
   AUTHOR			: Siddharam Pujari
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created in 2008 as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 17/08/2009
   NOTES			:
   VERSION HISTORY	: 2.5.1.03
=============================================================================*/


#include "pch.h"
#include "GenericScanner.h"
#include "SDSAConstants.h"


/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: 
	Out Parameters	: void
	Purpose			: Scan Function
	Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CGenericScanner::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	if(IsStopScanningSignaled())
		return ( false ) ;

	MakeListofLocations() ;
	CheckShellExecHook();
	CheckSharedTask(STS_PATH);

#ifdef WIN64
	CheckToolBar(TOOLBAR_REGISTRY_PATH_IE_X64 , HKEY_LOCAL_MACHINE , HKLM , true) ;
#else
	CheckToolBar( TOOLBAR_REGISTRY_PATH_IE , HKEY_LOCAL_MACHINE , HKLM ) ;
#endif

	CheckBHO();
	CheckSSODL ();

#ifdef WIN64
	CheckMenuExtension (MENUEXTENSION_REGISTRY_INFO_X64 , HKEY_LOCAL_MACHINE , HKLM ) ;
#else
	CheckMenuExtension(MENUEXTENSION_REGISTRY_INFO , HKEY_LOCAL_MACHINE , HKLM ) ;
#endif

	if (m_bSplSpyFound)
		return (m_bSplSpyFound);
	else
		return false ;
}
	
/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: Hive name, Hive Type & Key
	Out Parameters	: void
	Purpose			: to scan Sharedtask entries
	Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/
	
bool CGenericScanner::CheckSharedTask( CString csSTS, bool bWow6432Node)
{
	try
	{
		CStringArray oValueArr,oDataArr;
		bool bFound = false ;
		CString csTemp = _T("\\");
		CString csData ;
		CString csTempData;

		if(IsStopScanningSignaled())
			return ( false ) ;

		m_objReg. QueryDataValue ( csSTS , oValueArr , oDataArr , HKEY_LOCAL_MACHINE ) ;

		for ( int i = 0 ; i < oValueArr . GetCount() ; i++ )
		{
			bFound = false;
			if ( !bFound )
			{
				m_objReg.Get(STS_PATH , oValueArr [ i ], csTempData, HKEY_LOCAL_MACHINE) ;
	            
#ifdef WIN64
					bFound = m_objGenFileScan . CheckFileInCLSID ( oValueArr [ i ] , csData , m_csArrSpyLocation , true ) ;    
#else
					bFound = m_objGenFileScan . CheckFileInCLSID ( oValueArr [ i ] , csData , m_csArrSpyLocation , false ) ;
#endif
				if ( bFound ) 
				{
					m_bSplSpyFound = true;
					CString csValue = oValueArr [ i ];
#ifdef WIN64
					CString csKeyToEnum  = HKLM + csTemp+ ACTIVEX_REGISTRY_INFO_X64 + oValueArr [ i ];
#else
					CString csKeyToEnum = HKLM + csTemp + CLSID_KEY + oValueArr [ i ] ;
#endif
					SendScanStatusToUI ( Special_RegVal,12038,HKEY_LOCAL_MACHINE , CString(STS_PATH) ,
											 csValue , REG_SZ ,(LPBYTE)(LPCTSTR)csTempData,(csTempData.GetLength())* 2);
					EnumKeynSubKey (csKeyToEnum,12038);
					SendScanStatusToUI  ( Special_File ,12038,csData );
				}
				
			}
			if(IsStopScanningSignaled())
				return ( false ) ;
		}
			return ( m_bSplSpyFound );
	}
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
return ( false );
}

/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: Hive name, Hive Type & Key
	Out Parameters	: void
	Purpose			: to scan BHO entries
	Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/

bool CGenericScanner::CheckBHO()
{
	try
	{
		CStringArray oValueArr,oDataArr;
		bool bFound = false ;
		CString csTemp = _T("\\");
		CString csFullKey;
		CString sBHOKey;
		CString csTempData;
		CString csData;

		
		if(IsStopScanningSignaled())
			return ( false ) ;
	
		CMapStringToString oSubKeys;
#ifdef WIN64
		m_oRegistry.EnumSubKeys(BHO_REGISTRY_PATH_X64, oSubKeys, HKEY_LOCAL_MACHINE);
#else
		m_oRegistry.EnumSubKeys(BHO_REGISTRY_PATH, oSubKeys, HKEY_LOCAL_MACHINE);
#endif

		if(oSubKeys.GetCount() == 0)
			return ( false );

		
		for( POSITION pos = oSubKeys.GetStartPosition(); pos != NULL; )
		{
			if(IsStopScanningSignaled())
				return ( false ) ;

			bFound = false;
			if ( !bFound )
			{
				sBHOKey = "";
				oSubKeys.GetNextAssoc( pos, csFullKey, sBHOKey );
				
#ifdef WIN64
				bFound = m_objGenFileScan . CheckFileInCLSID ( sBHOKey , csData , m_csArrSpyLocation ,  true ) ;
#else
				bFound = m_objGenFileScan . CheckFileInCLSID ( sBHOKey , csData , m_csArrSpyLocation ,  false ) ;
#endif
				if ( bFound ) 
				{
					m_bSplSpyFound = true;
#ifdef WIN64
					CString csKeyClsidToEnum = HKLM + csTemp + ACTIVEX_REGISTRY_INFO_X64 + sBHOKey ;
					CString csKeyBHOToEnum = HKLM + csTemp + BHO_REGISTRY_PATH_X64  + csTemp+ sBHOKey ;
#else
					CString csKeyClsidToEnum = HKLM + csTemp + CLSID_KEY + sBHOKey ;		
					CString csKeyBHOToEnum = HKLM + csTemp + BHO_REGISTRY_PATH  + csTemp+ sBHOKey ;
#endif
					EnumKeynSubKey (csKeyBHOToEnum,12035);
					EnumKeynSubKey (csKeyClsidToEnum,12035);
					SendScanStatusToUI  ( Special_File ,12035,csData );
				}
			}
		}
		return ( m_bSplSpyFound );
		}
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
return ( false );
}

/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: Hive name, Hive Type & Key
	Out Parameters	: void
	Purpose			: to scan ShellExecute Hook entries
	Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/

bool CGenericScanner::CheckShellExecHook ()
{
	try
	{
		CStringArray oValueArr;
		bool bFound = false ;
		CString csData ;
		CString csTempData;
		CString csTemp = _T("\\");

			
		if(IsStopScanningSignaled())
			return ( false ) ;
				
#ifdef WIN64
		//Get all SEH entries
		m_oRegistry . EnumValues ( SHELL_EXEC_HOOKS_X64 , oValueArr , HKEY_LOCAL_MACHINE ) ;
#else
			m_objReg . EnumValues ( SHELL_EXEC_HOOKS , oValueArr , HKEY_LOCAL_MACHINE ) ;
#endif
					
		for ( int i = 0 ; i < oValueArr . GetCount() ; i++ )
		{
			if(IsStopScanningSignaled())
				return ( false ) ;

			bFound = false;

			if ( !bFound )
			{
#ifdef WIN64
				CString csKeyToEnum = HKLM + csTemp + ACTIVEX_REGISTRY_INFO_X64 + oValueArr [ i ] ;
#else
				CString csKeyToEnum = HKLM + csTemp + CLSID_KEY + oValueArr [ i ] ;
#endif
				m_objReg.Get(SHELL_EXEC_HOOKS , oValueArr [ i ], csTempData, HKEY_LOCAL_MACHINE) ;
#ifdef WIN64
				bFound  = m_objGenFileScan . CheckFileInCLSID ( oValueArr [ i ] , csData , m_csArrSpyLocation ,  true  ) ;
#else
				bFound  = m_objGenFileScan . CheckFileInCLSID ( oValueArr [ i ] , csData , m_csArrSpyLocation ,  false  ) ;
#endif
				if ( bFound )
				{
					m_bSplSpyFound = true;
					CString csValue = oValueArr [ i ];
					SendScanStatusToUI ( Special_RegVal , 12024, HKEY_LOCAL_MACHINE , CString(SHELL_EXEC_HOOKS) ,
                                         csValue , REG_SZ ,(LPBYTE)(LPCTSTR)csTempData,(csTempData.GetLength())* 2);
					EnumKeynSubKey ( csKeyToEnum , 12024, true );
					SendScanStatusToUI  ( Special_File ,12024,csData );
					AddToCompulsoryDeleteOnRestartList ( RD_VALUE , 12024 ,
						CString ( HKLM ) + BACK_SLASH + SHELL_EXEC_HOOKS + BACK_SLASH + _T ( "\t#@#" ) + csValue ) ;
				}
			}
		}
		return ( m_bSplSpyFound );
	}
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: Hive name, Hive Type & Key
	Out Parameters	: void
	Purpose			: to scan menu extension entries
	Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/

bool CGenericScanner::CheckToolBar (const CString& csRegKey , HKEY hHive , const CString& csHiveName, bool bX64Check )
{
	 try
	 {
		CStringArray oValueArr , oDataArr ;
		bool bFound = false ;
		CString csTemp = _T("\\") ;
		CString csData ;
		CString csTempData;

		if(IsStopScanningSignaled())
				return ( false ) ;

		m_oRegistry . EnumValues ( csRegKey , oValueArr , hHive ) ;

		for ( int i = 0 ; i < oValueArr . GetCount() ; i++ )
		{
			if(IsStopScanningSignaled())
				return ( false ) ;

			bFound = false;
			if ( !bFound )
			{
			
#ifdef WIN64
			CString csKeyToEnum = HKLM + csTemp + CLSID_KEY + oValueArr [ i ] ;
#else
			CString csKeyToEnum = HKLM + csTemp + CLSID_KEY + oValueArr [ i ] ;
#endif
			m_objReg.Get(TOOLBAR_REGISTRY_PATH_IE , oValueArr [ i ], csTempData, HKEY_LOCAL_MACHINE) ;
#ifdef WIN64
			bFound = m_objGenFileScan . CheckFileInCLSID ( oValueArr [ i ] , csData , m_csArrSpyLocation , true ) ;
#else
			bFound = m_objGenFileScan . CheckFileInCLSID ( oValueArr [ i ] , csData , m_csArrSpyLocation , false ) ;
#endif
				if ( bFound )
				{
					m_bSplSpyFound = true;
					CString csValue = oValueArr [ i ];
					SendScanStatusToUI ( Special_RegVal , 12037 , HKEY_LOCAL_MACHINE , CString(TOOLBAR_REGISTRY_PATH_IE) ,
											csValue , REG_SZ ,(LPBYTE)(LPCTSTR)csTempData,(csTempData.GetLength())* 2);
					EnumKeynSubKey (csKeyToEnum,12037);
					SendScanStatusToUI  ( Special_File ,12037,csData );
				}
			}
		}
			return ( m_bSplSpyFound );
		}
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: Hive name, Hive Type & Key
	Out Parameters	: void
	Purpose			: to scan menu extension entries
	Author			: Siddharam pujari
--------------------------------------------------------------------------------------*/

bool CGenericScanner::CheckMenuExtension (const CString& csRegKey , HKEY hHive , const CString& csHiveName, bool bX64Check )
{
	try
	{
		CStringArray oSubKeysArr ;
		CString csClsidData ;
		bool bFound = false ;
		CString csTemp = _T("\\") ;
		CString csData;
		
		if(IsStopScanningSignaled())
				return ( false ) ;

		m_oRegistry . EnumSubKeys ( csRegKey , oSubKeysArr , hHive ) ;

		for ( int i = 0 ; i < oSubKeysArr . GetCount() ; i++ )
		{
			if(IsStopScanningSignaled())
				return ( false ) ;

			bFound = false;

			m_oRegistry . Get ( csRegKey + _T("\\") + oSubKeysArr [ i ] , _T("CLSID") , csClsidData , hHive ) ; 
			
			if ( !bFound )
			{
			
#ifdef WIN64
			CString csKeyClsidToEnum = HKLM + csTemp + ACTIVEX_REGISTRY_INFO_X64 + oSubKeysArr [ i ] ;
#else
			CString csKeyClsidToEnum = HKLM + csTemp + CLSID_KEY + csClsidData ;
#endif
			CString csKeyMenuExToEnum = csHiveName + _T("\\") + csRegKey + _T("\\") + oSubKeysArr [ i ] ;
						
#ifdef WIN64
			if ( 0 != csClsidData . GetLength() )
			{
					bFound = m_objGenFileScan . CheckFileInCLSID ( csClsidData , csData , m_csArrSpyLocation ,  true ) ;
//					csSpywareName = csSpyName ;
			}
#else
			if ( 0 != csClsidData . GetLength() )
			{
					bFound = m_objGenFileScan . CheckFileInCLSID ( csClsidData , csData , m_csArrSpyLocation ,  false );
			}
#endif
			if ( bFound )
			{
				m_bSplSpyFound = true;
				EnumKeynSubKey (csKeyClsidToEnum,12040);
				EnumKeynSubKey (csKeyMenuExToEnum,12040);
				SendScanStatusToUI  ( Special_File ,12040,csData );
			}
		}
	}
		return ( m_bSplSpyFound );
	}
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan
	In Parameters	: CSpyScanner *pSpyScanner : Scanner pointer 
	Out Parameters	: void
	Purpose			: to scan menu SSODL entries
	Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/

bool CGenericScanner::CheckSSODL ()
{
	try
	{
		CStringArray oValueArr,oDataArr;
		CString csTemp = _T("\\");
		CString csData;
		CString csTempData;
		bool bFound;

#ifdef WIN64
		m_oRegistry.QueryDataValue(SSODL_PATH_X64,oValueArr,oDataArr,HKEY_LOCAL_MACHINE);
#else
		m_oRegistry.QueryDataValue(SSODL_PATH,oValueArr,oDataArr,HKEY_LOCAL_MACHINE);
#endif
		
		for(int i = 0; i < oValueArr.GetCount(); i++)
		{

			if(IsStopScanningSignaled())
				return ( false ) ;

			bFound = false;

			if ( !bFound )
			{
								
#ifdef WIN64
				CString csKeyClsidToEnum = HKLM + csTemp + ACTIVEX_REGISTRY_INFO_X64 + oDataArr . GetAt ( i ) ;
				//CString csKeySSODLToEnum = HKLM + csTemp + SSODL_PATH_X64 + oValueArr.GetAt(i);
				m_objReg.Get(SSODL_PATH_X64 , oValueArr [ i ], csTempData, HKEY_LOCAL_MACHINE) ;
#else
				CString csKeyClsidToEnum = HKLM + csTemp + CLSID_KEY + oDataArr . GetAt ( i ) ;
				m_objReg.Get(SSODL_PATH , oValueArr [ i ], csTempData, HKEY_LOCAL_MACHINE) ;
#endif

#ifdef WIN64
				bFound = m_objGenFileScan . CheckFileInCLSID ( oDataArr . GetAt ( i ) , csData , m_csArrSpyLocation , true ) ;
#else
				bFound = m_objGenFileScan . CheckFileInCLSID ( oDataArr . GetAt ( i ) , csData ,  m_csArrSpyLocation  ) ;
#endif
				if ( bFound ) 
				{
					m_bSplSpyFound = true ;
					CString csValue = oValueArr [ i ];				
					SendScanStatusToUI ( Special_RegVal , 12036, HKEY_LOCAL_MACHINE , CString(SSODL_PATH) ,
                                        csValue , REG_SZ ,(LPBYTE)(LPCTSTR)csTempData,(csTempData.GetLength())* 2);
					EnumKeynSubKey (csKeyClsidToEnum,12036);
					SendScanStatusToUI  ( Special_File ,12036,csData );
					
				}
			}
		}
		return ( m_bSplSpyFound );
	}
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: MakeListofLocations
	In Parameters	: -
	Out Parameters	: void
	Purpose			: Make the list of all locations where to check the Suspicious file
	Author			: Vaibhav Desai
--------------------------------------------------------------------------------------*/
void CGenericScanner :: MakeListofLocations()
{
	TCHAR szPath [ MAX_PATH ] = { 0 } ;
	LPTSTR strUserName = NULL ;	
	LPVOID posUserName ;
	CString csFilePath ;

	LoadAvailableUsers () ;
	
	m_csArrSpyLocation . Add ( CSystemInfo::m_strSysDir ) ;
	m_csArrSpyLocation . Add ( CSystemInfo::m_strWinDir ) ;

	SHGetFolderPath ( 0 , CSIDL_LOCAL_APPDATA , 0 , 0 , szPath ) ; // get user local setting application data path
	CString csLocalAppPath ( szPath ) ;
	csLocalAppPath . MakeLower() ;

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
		m_csArrSpyLocation . Add ( csUserPath + csAppPath ) ;
		posUserName = m_objAvailableUsers . GetNext ( posUserName ) ;
	}

	SHGetFolderPath ( 0 , CSIDL_COMMON_APPDATA , 0 , 0 , szPath  ) ; // get all user application data path
	m_csArrSpyLocation . Add ( szPath ) ;
	
	m_csArrSpyLocation . Add ( CSystemInfo::m_strWinDir + _T( "\\Fonts" ) ) ;
	m_csArrSpyLocation . Add ( CSystemInfo::m_strWinDir + _T( "\\Tasks" ) ) ;
	m_csArrSpyLocation . Add ( CSystemInfo::m_strWinDir + _T( "\\Downloaded Program Files" ) ) ;
}