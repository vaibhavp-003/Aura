/*=======================================================================================
   FILE				: QuakeWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware QuakeWorm
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
#include "quakeworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForSpywareQuake
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove Spyware Quake
	Author			: Anand
	Description		: run uninstaller for SpywareQuake
--------------------------------------------------------------------------------------*/
bool CQuakeWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
				return false;

		bool bFound = false ;

		//Version: 18.9.0.003
		//Resource: Anand
	
		if ( !bToDelete )
			_CheckForCodecFolder() ;

		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("SpywareQuake") , _T("uninst.exe") ,
												   _T("/S"), bToDelete, m_ulSpyName ) ;
		if ( bFound && bToDelete )
		{
			KillProcess ( _T("SpywareQuake") , _T("SpywareQuake.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}
		m_bSplSpyFound = bFound ? true : m_bSplSpyFound ;

		if ( m_bScanOtherLocations )
		{
			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("SpywareQuake") , _T("uninst.exe") ,
													   _T("/S"), bToDelete, m_ulSpyName ) ;
			if ( bFound && bToDelete )
			{
				KillProcess ( _T("SpywareQuake") , _T("SpywareQuake.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}
			m_bSplSpyFound = bFound ? true : m_bSplSpyFound ;
		}

		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("SpywareQuake.Com") , _T("uninst.exe") ,
												   _T("/S") , bToDelete , m_ulSpyName ) ;
		if ( bFound && bToDelete )
		{
			KillProcess ( _T("SpywareQuake.Com") , _T("Spyware-Quake.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}

		m_bSplSpyFound = bFound ? true : m_bSplSpyFound ;

		if ( m_bScanOtherLocations )
		{
			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("SpywareQuake.Com") , _T("uninst.exe") ,
													   _T("/S") , bToDelete , m_ulSpyName ) ;
			if ( bFound && bToDelete )
			{
				KillProcess ( _T("SpywareQuake.Com") , _T("Spyware-Quake.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}

			m_bSplSpyFound = bFound ? true : m_bSplSpyFound ;
		}

		//version: 19.0.0.29
		//resource: Anand
		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("SpywareQuaked") , _T("uninst.exe") ,
												   _T("/S") , bToDelete , m_ulSpyName ) ;
		if ( bFound && bToDelete )
		{
			KillProcess ( _T("SpywareQuaked") , _T("SpywareQuaked.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}
		m_bSplSpyFound = bFound ? true : m_bSplSpyFound ;

		if ( m_bScanOtherLocations )
		{
			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("SpywareQuaked") , _T("uninst.exe") ,
													   _T("/S") , bToDelete , m_ulSpyName ) ;
			if ( bFound && bToDelete )
			{
				KillProcess ( _T("SpywareQuaked") , _T("SpywareQuaked.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}
			m_bSplSpyFound = bFound ? true : m_bSplSpyFound ;
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CQuakeWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForCodecFolder
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check for Codec folder in Program Files
	Author			: Anand
	Description		: check spyware quake related Codec folders in %pfdir%
--------------------------------------------------------------------------------------*/
bool CQuakeWorm :: _CheckForCodecFolder ( void )
{
	try
	{
		CString csFullFileName ;
		BOOL bMoreFiles = FALSE ;
		CStringArray csArrLocations ;

		if(IsStopScanningSignaled())
			return ( false ) ;

		csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherPFDir ) ;

		CFileFind  objFile;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			bMoreFiles = objFile.FindFile ( csArrLocations [ i ] + _T("\\*.*") ) ;
			while ( bMoreFiles )
			{
				bMoreFiles = objFile.FindNextFile() ;
				if ( objFile.IsDots() )
					continue ;

				if(IsStopScanningSignaled())
					break ;

				if ( objFile.IsDirectory() )
				{
					if ( CheckIfCodecFolder( objFile.GetFilePath()))
					{
						RemoveFolders( objFile.GetFilePath(), m_ulSpyName , false ) ;
						_DisplayOtherEntriesInUI ( objFile.GetFilePath() ) ;
					}
				}
			}

			objFile.Close() ;
		}

		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CQuakeWorm::_CheckForCodecFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: DisplayOtherEntriesInUI
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check for entries of Codec in registry
	Author			: Anand
	Description		: search and display Codec related entries in UI
--------------------------------------------------------------------------------------*/
bool CQuakeWorm :: _DisplayOtherEntriesInUI ( CString csFolder )
{
	try
	{
		CStringArray csArrSubKey ;
		CString csHold ;

		// the path coming here must be %pfdir%\somefolder, check for it
		if ( _tcsnicmp ( csFolder , CSystemInfo :: m_strProgramFilesDir , _tcslen ( CSystemInfo :: m_strProgramFilesDir ) ) ||
			 _tcslen ( csFolder ) <= _tcslen ( CSystemInfo :: m_strProgramFilesDir ) )
		{
			// sanity check for folder name failed
			return ( false ) ;
		}

		// now check for entries in policies\explorer\run
        vector<REG_VALUE_DATA> vecRegValues;
	    m_objReg.EnumValues(POL_EXPL_RUN_PATH, vecRegValues, HKEY_LOCAL_MACHINE);		
		{
            for ( size_t i = 0 ; i < vecRegValues.size() ; i++ )
			{
                if ( vecRegValues[i].bData == NULL )
					continue ;

				if(IsStopScanningSignaled())
					break ;
                CString csData;
                csData.Format(_T("%s") , (TCHAR*)vecRegValues[i].bData);

				if ( !_tcsnicmp( csData, csFolder, _tcslen(csFolder)))
				{
                    SendScanStatusToUI ( Special_RegVal, m_ulSpyName , HKEY_LOCAL_MACHINE, CString(POL_EXPL_RUN_PATH) ,vecRegValues[i].strValue,vecRegValues[i].Type_Of_Data,vecRegValues[i].bData,vecRegValues[i].iSizeOfData ) ;
				}
			}
		}

		// now check in BHOs
		if ( m_objReg.EnumSubKeys( BHO_REGISTRY_PATH, csArrSubKey, HKEY_LOCAL_MACHINE ) )
		{
			for ( int i = 0 ; i < csArrSubKey.GetCount() ; i++ )
			{
				if(IsStopScanningSignaled())
					break ;

				if ( SearchPathInCLSID( csArrSubKey[i], csFolder, m_ulSpyName ) )
				{
					SendScanStatusToUI ( Special_RegKey, m_ulSpyName ,HKEY_LOCAL_MACHINE,  CString(BHO_REGISTRY_PATH) 
						+ CString(BACK_SLASH) + csArrSubKey [ i ]  ,0,0,0,0 ) ;
				}
			}
		}

		// now check for entries in policies\explorer\run
       vector<REG_VALUE_DATA> vecRegValues1;
	    m_objReg.EnumValues(TOOLBAR_REGISTRY_PATH, vecRegValues1, HKEY_LOCAL_MACHINE);		
		{
            for ( size_t i = 0 ; i < vecRegValues1.size() ; i++ )
			{
				if ( vecRegValues1[i].bData == NULL )
					continue ;

				if(IsStopScanningSignaled())
					break ;

                if ( SearchPathInCLSID ( vecRegValues1[i].strValue, csFolder, m_ulSpyName ) )
				{
                    SendScanStatusToUI (Special_RegVal ,  m_ulSpyName ,HKEY_LOCAL_MACHINE, CString(TOOLBAR_REGISTRY_PATH) ,
                        vecRegValues1[i].strValue,vecRegValues1[i].Type_Of_Data,vecRegValues1[i].bData,vecRegValues1[i].iSizeOfData) ;					
				}
			}
		}
		return true;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CQuakeWorm::_CheckHotBarRandomEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
