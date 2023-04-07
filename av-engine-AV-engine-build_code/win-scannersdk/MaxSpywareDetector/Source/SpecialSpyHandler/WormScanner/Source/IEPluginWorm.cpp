/*====================================================================================
   FILE				: IEPluginWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware IEPlugin
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
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
#include "iepluginworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForIEPlugIn
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and clean IEPlugin
	Author			: Anand
	Description		: removes Command.exe service and random folder in Windows folder
					  and Program files
--------------------------------------------------------------------------------------*/
bool CIEPluginWorm::ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;
	
		if(IsStopScanningSignaled())
			return false;

		bool bConfirm = false ;
		CString csServiceFolderName, csServiceFileName ;
			
		if( FindReportKillServiceOnRestart(_T("cmdService") ,m_ulSpyName, csServiceFileName, csServiceFolderName, bToDelete))
			m_bSplSpyFound = true;

		if ( m_bSplSpyFound && !bToDelete)
		{
			bConfirm = false ;
			_DetermineIfIEPluginFolders ( &bConfirm , csServiceFolderName ) ;
		}

		if ( !bToDelete )
			_DeleteIEFoldersAndKeys ( csServiceFolderName , csServiceFileName , m_ulSpyName,  bToDelete ) ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CIEPluginWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: DetermineIfIEPluginFolders 
	In Parameters	: 
	Out Parameters	: bool * , CString&
	Purpose			: Finds IEPlugin folder
	Author			: 
	Description		: Finds and returns foldername in csFolderName
--------------------------------------------------------------------------------------*/
bool CIEPluginWorm::_DetermineIfIEPluginFolders ( bool * bConfirm , CString& csFolderName )
{
	try
	{
		if(IsStopScanningSignaled())
			return false;
		    
		BOOL bFound = FALSE ;
		CStringArray csLocations ;

		csLocations . Add ( CSystemInfo :: m_strSysDir ) ;
		if ( m_bScanOtherLocations )
			csLocations . Add ( m_csOtherSysDir ) ;

		for ( int i = 0 ; i < csLocations .GetCount() ; i++ )
		{
			CString csSearchPath = csLocations [ i ] + BACK_SLASH + _T("*") ;

			CFileFind  objFile;

			bFound = objFile.FindFile ( csSearchPath ) ;
			while ( bFound )
			{
				bFound = objFile.FindNextFile() ;

				if ( objFile.IsDots() || !objFile.IsDirectory() )
					continue ;

				CString csFullFileName ;
				csFullFileName = csLocations [ i ] + BACK_SLASH + objFile.GetFileName() + BACK_SLASH +
								objFile.GetFileName() + _T(".dat") ;

				if ( !_taccess_s ( csFullFileName , 0 ) )
				{
					* bConfirm = true ;
					csFolderName = objFile.GetFileName() ;
					break ;
				}
			}

			objFile.Close() ;
		}

		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CIEPluginWorm::_DetermineIfIEPluginFolders, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: _DeleteIEFoldersAndKeys 
	In Parameters	: 
	Out Parameters	: bool
 	Purpose			: 
	Author			: 
	Description		: 
--------------------------------------------------------------------------------------*/
bool CIEPluginWorm::_DeleteIEFoldersAndKeys ( CString csFolderName , CString csServiceFileName, ULONG ulSpywareName, bool bToDelete )
{	
	try
	{
		if( IsStopScanningSignaled())
		return false;

		if ( !csFolderName.IsEmpty() )
		{
			RemoveFolders(m_objSysInfo.m_strProgramFilesDir + _T("\\Network Monitor"), ulSpywareName, bToDelete);
			RemoveFolders(m_objSysInfo.m_strProgramFilesDir + _T("\\Common Files\\") + csFolderName , ulSpywareName, bToDelete);
			RemoveFolders(m_objSysInfo.m_strProgramFilesDir + _T("\\") + csFolderName, ulSpywareName, bToDelete);

			if ( m_bScanOtherLocations )
			{
				RemoveFolders(m_csOtherPFDir + _T("\\Network Monitor"), ulSpywareName, bToDelete);
				RemoveFolders(m_csOtherPFDir + _T("\\Common Files\\") + csFolderName , ulSpywareName, bToDelete);
				RemoveFolders(m_csOtherPFDir + _T("\\") + csFolderName, ulSpywareName, bToDelete);
			}

			if(m_objReg.KeyExists(_T("SOFTWARE\\") + csFolderName, HKEY_LOCAL_MACHINE))
			{
				SendScanStatusToUI ( Special_RegKey, ulSpywareName , HKEY_LOCAL_MACHINE , CString(SOFTWARE_PATH) + CString(BACK_SLASH) + csFolderName,0,0,0,0  ) ;
			}

			if ( m_bScanOtherLocations )
			{
				if(m_objReg.KeyExists(WOW6432NODE_REG_PATH + csFolderName, HKEY_LOCAL_MACHINE))
				{
                    SendScanStatusToUI ( Special_RegKey , ulSpywareName , HKEY_LOCAL_MACHINE, 
                        CString(WOW6432NODE_REG_PATH) + CString(BACK_SLASH) + csFolderName,0,0,0,0  ) ;
				}
			}
		}

		if ( !csServiceFileName.IsEmpty())
		{
			csServiceFileName = csServiceFileName . Left ( csServiceFileName . ReverseFind ( '\\' ) ) ;
			RemoveFolders( csServiceFileName , ulSpywareName, bToDelete);
		}

		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CIEPluginWorm::_CheckHotBarRandomEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
