/*======================================================================================
   FILE				: GenActiveSetup.cpp
   ABSTRACT			: This class is used for scanning and qurantining GenActiveSetup
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
   CREATION DATE	: 20/11/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.52
					Resource : Shweta
					Description: created this class to fix Actve setup install components entries
					
					version: 2.5.1.14
					Resource : Shweta
					Description: handled Bifrose infection

========================================================================================*/

#include "pch.h"
#include "GenActiveSetup.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove activesetup random entries
	Author			: Shweta M
	Description		: This function checks activesetup random entries and removes them on restart
--------------------------------------------------------------------------------------*/
bool CGenActiveSetupICWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
	
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		if ( CheckforActiveSetupEntries(ACTIVESETUP_INSTALLCOMPONENTS, bToDelete) )
			m_bSplSpyFound = true ;

		CheckforMicrosoftKey ( bToDelete ) ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}
	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CGenActiveSetupICWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckforMicrosoftKey
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove random entries of bifrose
	Author			: Shweta M
	Description		: This function checks for random entries in HKLM\Software path
--------------------------------------------------------------------------------------*/
bool CGenActiveSetupICWorm  :: CheckforMicrosoftKey ( bool bToDelete )
{
	bool bBifroseInfection = false ;
	CStringArray csArrSubKeys ;
	CString csKey,csNewKey;
	
	CStringArray csArrkeys;

	if ( _taccess ( m_objSysInfo.m_strProgramFilesDir + _T("\\Bifrose") ,0 ) )
	{
		RemoveFolders ( m_objSysInfo.m_strProgramFilesDir + _T("\\Bifrose") , 848 , false ); 
		bBifroseInfection = true ;
	}

	if ( _taccess ( m_objSysInfo.m_strProgramFilesDir + _T("\\Bifrost") ,0 ) )
	{
		RemoveFolders ( m_objSysInfo.m_strProgramFilesDir + _T("\\Bifrost") , 848 , false ); 
		bBifroseInfection = true ;
	}

	if ( bBifroseInfection || m_bSplSpyFound )
	{
		if ( !m_objReg.EnumSubKeys ( SOFTWARE, csArrSubKeys , HKEY_LOCAL_MACHINE ) )
			return false;

		for ( INT_PTR j = 0 ,jtotal = csArrSubKeys.GetCount(); j < jtotal ; j++ )
		{
			csKey = csArrSubKeys.GetAt(j) ;
			csKey.MakeLower();
			if (csKey == _T("microsoft") )
				continue;

			csNewKey.Format(_T("%s%s%s\\Active Setup\\Installed Components"),SOFTWARE , BACK_SLASH , csKey ) ;
			if (! m_objReg.KeyExists(csNewKey , HKEY_LOCAL_MACHINE) )
				continue;

			//call same function with install components path as is key name
			CheckforActiveSetupEntries ( csNewKey , bToDelete);		
		}
	}
	return false ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckforActiveSetupEntries
	In Parameters	: CString , bool
	Out Parameters	: 
	Purpose			: Check and remove random entries of bifrose
	Author			: Shweta M
	Description		: This function checks for random entries in HKLM\Software path
--------------------------------------------------------------------------------------*/
bool CGenActiveSetupICWorm:: CheckforActiveSetupEntries(const CString & csKeyToenum , bool bToDelete)
{
	CFileVersionInfo objVer;
	CArray<CString,CString> csArrKey ;
	CString csValue, csFileName, csKey, csFolder;
	
	//Enumerate ACTIVESETUP_INSTALLCOMPONENTS

	if (! m_objReg.EnumSubKeys ( csKeyToenum , csArrKey , HKEY_LOCAL_MACHINE ) )
		return false;

	for ( INT_PTR i = 0 ,itotal = csArrKey.GetCount(); i < itotal ; i++ )
	{
		if ( ( csArrKey.GetAt(i).Find ( _T("<{") )!= -1 ) || ( csArrKey.GetAt(i).Find ( _T(">{") )!= -1 ) )
			continue ;

		csKey.Format (_T("%s"),csArrKey.GetAt(i) );
		if (! m_objReg.Get (  csKey, _T("stubpath") ,csValue , HKEY_LOCAL_MACHINE ) )
			continue ;

		csValue.MakeLower();
		if ( ( csValue.Find ( _T("regsvr32.exe"))!= -1) || ( csValue.Find ( _T("rundll32.exe") )!= -1) )
			continue;

		if ( ( csValue.Find ( _T("\\system32\\") ) != -1 ) || ( csValue.Find ( _T("\\windows\\") ) != -1 ) )
		{
			if ( csValue.Find ( _T(" ") ) != -1 )
				csFileName = csValue.Left( csValue.Find (_T(" ")) )  ;
			else
				csFileName = csValue ;
			if ( _taccess ( csFileName , 0 ) != 0 )
				continue;

			if ( objVer.DoTheVersionJob ( csFileName , false ) )
			{
				if (bToDelete)
				{
					EnumKeynSubKey ( CString( HKLM )+ BACK_SLASH + csKey , m_ulSpyName , true ) ;
					AddInRestartDeleteList( RD_FILE_DELETE , m_ulSpyName  , csFileName) ;
				}
				else
				{
					EnumKeynSubKey ( CString( HKLM )+ BACK_SLASH + csKey , m_ulSpyName , true ) ;
					SendScanStatusToUI ( Special_File_Report , m_ulSpyName  , csFileName) ;
					m_bSplSpyFound =  true;
				}
			}
		}
		else if ( ( csValue.Find( _T("\\bifrose\\") ) !=-1 ) || ( csValue.Find( _T("\\bifrost\\") ) !=-1 ) )
		{
			//check for bifrose in the path
			csFileName = csValue.Left( csValue.ReverseFind (' ') ) ;
			csFileName.Replace ( _T("\"") , BLANKSTRING );
			if ( _taccess ( csFileName , 0 ) != 0 )
				continue;

			if ( objVer.DoTheVersionJob ( csFileName , false ) )
			{
				csFolder = csFileName.Left ( csFileName.ReverseFind (_T('\\') ) ) ;
				if (bToDelete)
				{
					EnumKeynSubKey ( CString( HKLM )+ BACK_SLASH + csKey , m_ulSpyName , true ) ;
					AddInRestartDeleteList( RD_FILE_DELETE , m_ulSpyName  , csFileName) ;
				}
				else
				{
					EnumKeynSubKey ( CString( HKLM )+ BACK_SLASH + csKey , m_ulSpyName , true ) ;
					SendScanStatusToUI ( Special_File_Report , 848  , csFileName) ;
					RemoveFolders( csFolder , 848 , false );
					m_bSplSpyFound =  true;
				}
			}
		}
	}
	return m_bSplSpyFound ;
}