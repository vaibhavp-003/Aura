/*====================================================================================
   FILE				: RandomEntries.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware with Random entries
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
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#include "pch.h"
#include <fcntl.h>
#include <sys/stat.h>
#include "randomentries.h"
#include "StringFunctions.h"
#include "SpecialSpyHandler.h"
#include "MaxDSrvWrapper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForRandomSpywareEntries
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for random spyware entries for different spywares
	Author			: Anand
	Description		: check and report to UI for different spyware entries
--------------------------------------------------------------------------------------*/
bool CRandomEntries :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
				return false;


		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.InitializeDatabase();
		if(bToDelete || !objMaxDSrvWrapper.IsExcluded(m_ulSpyName, L"", L""))
		{
			if ( CheckTrojanDownloader ( bToDelete , 7586 ) )
				m_bSplSpyFound = true ;

		}

		if(bToDelete || !objMaxDSrvWrapper.IsExcluded(m_ulSpyName, L"", L""))
		{            
			if ( CheckISearchEntries ( bToDelete , 3260 ) )
				m_bSplSpyFound = true ;
		}
		objMaxDSrvWrapper.DeInitializeDatabase();

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CRandomEntries::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckTrojanDownloader
	In Parameters	: bool , CString
	Out Parameters	: bool
	Purpose			: check for random entries of type trojan downloader
	Author			: Anand
	Description		: check for downloader entries in registry run key
					  this functions enumerates registry run entries and 
					  looks for a entry which has rundll32 in data and dlls name and parameter to rundll
					  are present in the dll and dll doesnt have version tab
--------------------------------------------------------------------------------------*/
bool CRandomEntries :: CheckTrojanDownloader ( bool bToDelete , ULONG ulSpywareName )
{
	bool bFound1 , bFound2 ;
	int i = 0 , hFile = -1 ;
	TCHAR * p = NULL ;
	TCHAR * comma = NULL ;	
	TCHAR szFullFileName [ MAX_PATH ] = { 0 } ;
	bool bDownloaderFound = false ;
	char Buf1 [ 200 ] = { 0 } ;
	char Buf2 [ 200 ] = { 0 } ;

	// if the function is called on quarantine, just do the the stuff and return false
	if ( bToDelete )
	{
		for ( i = 0 ; i < csArrRestartDeleteFiles.GetCount(); i++ )
			MoveFileEx ( csArrRestartDeleteFiles[i], NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

		return false;
	}

	csArrRestartDeleteFiles.RemoveAll();
	CStringArray csArrLocations ;

	csArrLocations . Add ( RUN_REG_PATH ) ;
	if ( m_bScanOtherLocations )
		csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;

	for ( i = 0 ; i < static_cast<int>( csArrLocations . GetCount() ) ; i++ )
	{
        vector<REG_VALUE_DATA> vecRegValues;
	    m_objReg.EnumValues(csArrLocations [ i ], vecRegValues, HKEY_LOCAL_MACHINE);        
        
        for ( size_t j = 0 ; j < vecRegValues.size(); j++ )
		{
            CString csData;
            csData.Format(_T("%s"),(TCHAR *)vecRegValues[j].bData);
            if ( csData == _T("") || vecRegValues[j].strValue == NULL)
				continue ;

			p = StrStrI ( csData, _T("rundll32.exe") ) ; // see if rundll32 exists in data
			if ( !p )
				continue ;

			p = _tcschr ( p , ' ' ) ; // search for space
			if ( !p )
				continue ;

			if ( !++p || !*p ) //skip space and point to dll filename
				continue ;

			comma = _tcschr ( p , ',' ) ; // look for comma to get the parameter
			if ( !comma )
				continue ;

			if ( _countof ( szFullFileName ) <= ( comma - p ) ) // check for buffer over run
				continue ;

			_tcsncpy_s ( szFullFileName , _countof ( szFullFileName ) , p , comma - p ); // copy dll filename

			//Resource:	Anand
			//Version: 19.0.0.20
			//added code to remove front and back double quotes

			//remove " ( double quotes ) from beginning and end of the dl name if present
			// remove from end
			if ( szFullFileName [ 0 ] && szFullFileName [ _tcslen ( szFullFileName ) - 1 ] == _T('"') )
				 szFullFileName [ _tcslen ( szFullFileName ) - 1 ] = _T('\0') ;

			// remove from beginning
			if ( szFullFileName [ 0 ] == _T('"') )
			{
				memmove ( szFullFileName , szFullFileName + 1 , _tcslen ( szFullFileName ) - 1 ) ;
				szFullFileName [ _tcslen ( szFullFileName ) - 1 ] = _T('\0') ;
			}

			CFileVersionInfo  oFileVersionInfo;
			if ( !oFileVersionInfo.DoTheVersionJob( szFullFileName , false ) )
				continue ;

			p = _tcsrchr ( szFullFileName , _T('\\') ) ; // get only file name from fullfilename
			if ( !p )
				continue ;

			if ( !++p || !*p ) // skip slash
				continue ;

			if ( !++comma || !*comma ) // skip comm
				continue ;

			// now 'comma' is pointing to parameter and 'p' is pointing to dllfilename
			// open file to search for keywords
			_tsopen_s ( &hFile , szFullFileName , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
			if ( -1 == hFile )
				continue ;

			// search for dllname and parameter
			bFound1 = bFound2 = false ;

#if defined _UNICODE || defined UNICODE
			for ( int index = 0 ; index < sizeof ( Buf1 ) && p [ index ] ; index++ )
				Buf1 [ index ] = (char) p [ index ] ;

			for ( int index = 0 ; index < sizeof ( Buf2 ) && p [ index ] ; index++ )
				Buf2 [ index ] = (char) p [ index ] ;
#else
			memset ( Buf1 , 0 , sizeof ( Buf1 ) ) ;
			_tcscpy_s ( Buf1 , _countof ( Buf1 ) , p ) ;
#endif

			SearchString ( hFile , Buf1 , &bFound1 ) ;
			SearchString ( hFile , Buf2 , &bFound2 ) ;
			_close ( hFile ) ;

			// check if both the parameter and filename were found
			if ( !bFound1 || !bFound2 )
				continue ;

			// send all the entries to UI ie file, value and data
			bDownloaderFound = true ;
			SendScanStatusToUI ( Special_File, ulSpywareName , szFullFileName  ) ;			
			SendScanStatusToUI ( Special_RegVal, ulSpywareName , HKEY_LOCAL_MACHINE ,  CString(RUN_REG_PATH) 
                , vecRegValues[j].strValue,vecRegValues[j].Type_Of_Data,vecRegValues[j].bData,vecRegValues[j].iSizeOfData) ;
		} 
	}
	return  bDownloaderFound ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckISearchEntries
	In Parameters	: bool , CString
	Out Parameters	: bool
	Purpose			: check for random entries of type ISearch
	Author			: Shweta M
	Description		: check for downloader entries in registry run key
					  this functions enumerates registry run entries and 
					  looks for a entry which has rundll32 in data and dlls name and parameter to rundll
					  are present in the dll and dll doesnt have version tab
--------------------------------------------------------------------------------------*/
bool CRandomEntries :: CheckISearchEntries ( bool bToDelete , ULONG ulSpywareName )
{
	//Enumerate HKLM\run Path n then find the entry having data as rundll32 and a dll file name 
	//with some random number check the files has those entries or not

	CStringArray	csSubKey ;	
	bool bRet = false;

	if(IsStopScanningSignaled())
		return ( false ) ;

	if ( bToDelete )
	{
		for ( int i = 0 ; i < csArrInfectedISearchFiles . GetCount() ; i++ )
			MoveFileEx ( csArrInfectedISearchFiles [ i ] , NULL , MOVEFILE_DELAY_UNTIL_REBOOT ) ;
		return ( false ) ;
	}
	else
		csArrInfectedISearchFiles.RemoveAll();

	CStringArray csArrLocation ;

	csArrLocation.Add ( RUN_REG_PATH ) ;
	if ( m_bScanOtherLocations )
		csArrLocation . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;

	for ( int i = 0 ; i < csArrLocation . GetCount() ; i++ )
	{

        vector<REG_VALUE_DATA> vecRegValues;
	    m_objReg.EnumValues(csArrLocation [ i ], vecRegValues, HKEY_LOCAL_MACHINE);		
		CFileVersionInfo oFileVersionInfo;
        for ( int j = 0 ; j < static_cast<int>( vecRegValues.size() ); j++ )
		{
			CStringArray csArrSysDirLocation ;

			csArrSysDirLocation . Add ( CSystemInfo::m_strSysDir ) ;
			if ( m_bScanOtherLocations )
				csArrSysDirLocation . Add ( m_csOtherSysDir ) ;

			for ( int a = 0 ; a < csArrSysDirLocation . GetCount() ; a++ )
			{
				CString csData;
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[j].bData);
				csData = csData.MakeLower();

				if ( -1 != csData . Find ( _T("rundll32.exe") ) )
				{
					CString csDllName;
                    csDllName.Format(_T("%s") , (TCHAR*)vecRegValues[j].bData);
					csDllName = csDllName.Right( csDllName.GetLength() - csDllName.Find(_T(" ")) -1 );
					csDllName = csDllName.Left(csDllName.Find(_T(",")));
					csDllName = csArrSysDirLocation [ a ] + BACK_SLASH + csDllName;
					
                    CString csValDllName = (CString)vecRegValues[j].strValue + _T(".dll");
					csValDllName = CSystemInfo::m_strSysDir + BACK_SLASH + csValDllName;
                    CString csSysfileName = csArrSysDirLocation [ a ] + BACK_SLASH + (CString)vecRegValues[j].strValue + _T(".sys");

					//Check if file Exists and the File does not have any version tab	
					if (_taccess_s(csSysfileName, 0) == 0)
					{
						if ( oFileVersionInfo.DoTheVersionJob ( csValDllName, false ) && oFileVersionInfo.DoTheVersionJob ( csDllName, false ))
						{
							bRet = true;
							SendScanStatusToUI ( Special_File , ulSpywareName , csValDllName  ) ;
							SendScanStatusToUI ( Special_File ,  ulSpywareName , csDllName  ) ;
							SendScanStatusToUI ( Special_File , ulSpywareName , csSysfileName  ) ;							
							SendScanStatusToUI ( Special_RegVal ,  ulSpywareName , HKEY_LOCAL_MACHINE , 
                                csArrLocation [ i ]  ,vecRegValues[j].strValue,vecRegValues[j].Type_Of_Data,vecRegValues[j].bData,vecRegValues[j].iSizeOfData) ;

							csArrInfectedISearchFiles . Add ( csValDllName ) ;
							csArrInfectedISearchFiles . Add ( csDllName ) ;
							csArrInfectedISearchFiles . Add ( csSysfileName ) ;
						}
					}
				}
			}      
        }
	}

	return ( bRet ) ;
}