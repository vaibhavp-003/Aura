/*====================================================================================
   FILE				: AntiVirGear.Cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware AntiVirGear
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

					version: 2.5.1.13
					Resource : Shweta
					Description: Added code for Antivirus systempro
========================================================================================*/

#include "pch.h"
#include "Antivirgear.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and remove Antivirgear
	Author			: Shweta
	Description		: Check AntivirGear folder 
--------------------------------------------------------------------------------------*/
bool CAntiVirGear::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		CFileFind objFF ;
		BOOL bFindFlag = FALSE ;
		CStringArray csArrScanLocations ;

		csArrScanLocations.Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrScanLocations.Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < (int)csArrScanLocations.GetCount() ; i++ )
		{
			bFindFlag =  objFF . FindFile ( csArrScanLocations [ i ] + _T("\\*.*") ) ;
			if ( !bFindFlag )
				continue ;

			while ( bFindFlag )
			{
				bFindFlag =  objFF . FindNextFile();
				if ( objFF . IsDots() || ! objFF . IsDirectory() )
					continue ;

				if ( IsSpywareFolder ( objFF . GetFilePath() , objFF . GetFileName() ) )
				{
					m_bSplSpyFound = true ;
					RemoveFolders ( objFF . GetFilePath() , m_ulSpyName , false ) ;
					CheckAndReportStartupFolder ( objFF . GetFileName() ) ;
				}
				else if ( CheckifAVSystemPro (  objFF . GetFilePath() , objFF . GetFileName() ) )
				{
					m_bSplSpyFound = true;
					RemoveFolders ( objFF . GetFilePath() , m_ulSpyName , false ) ;
				}
			}

			objFF . Close() ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CAntivirGear::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsSpywareFolder
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks pfdir and Startup programs for Antivir gear
	Author			: Shweta
	Description		: remove AntivirGear folder from PfDir and Startup Program 
--------------------------------------------------------------------------------------*/
bool CAntiVirGear :: IsSpywareFolder ( const CString& csFullFolderPath , const CString& csFolderName )
{
	CString csPath ;

	csPath = csFullFolderPath + BACK_SLASH + csFolderName + _T(".url") ;
	if ( _taccess_s ( csPath , 0 ) )
		return ( false ) ;

	csPath = csFullFolderPath + BACK_SLASH + csFolderName + _T(".exe") ;
	if ( _taccess_s ( csPath , 0 ) )
		return ( false ) ;

	csPath . MakeLower() ;
	if ( !CheckCompanyName ( csPath , _T("antivirgear.com") ) )
		return ( false ) ;

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndReportStartupFolder
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks Startup programs for Antivir gear
	Author			: Shweta
	Description		: remove AntivirGear folder from Startup Program 
--------------------------------------------------------------------------------------*/
bool CAntiVirGear :: CheckAndReportStartupFolder ( const CString& csFolderName )
{
	CString csPath ;
	TCHAR szSearchPath [ MAX_PATH ] = { 0 } ;

	SHGetFolderPath ( 0 , CSIDL_PROGRAMS , 0 , 0 , szSearchPath ) ;
	if ( 0 == szSearchPath [ 0 ] )
		return ( false ) ;

	csPath = CString ( szSearchPath ) + BACK_SLASH + csFolderName ;
	if ( !_taccess_s ( csPath , 0 ) )
		RemoveFolders ( csPath , m_ulSpyName , false ) ;

	return ( true ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckifAVSystemPro
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks programs folder for Antivirus System Pro
	Author			: Shweta
	Description		: remove Antivirus System Pro folder from Program files
--------------------------------------------------------------------------------------*/
bool CAntiVirGear :: CheckifAVSystemPro ( const CString& csFullFolderPath , const CString& csFolderName ) 
{
	CString csFile, csFileNm ;
	CFileFind objFileFind;
	BOOL bEntriesfound = FALSE;
	int icnt = 0 ;
	TCHAR CFileOriginalNm[MAX_PATH];
	bool bInfectionFound =  false;
	
	bEntriesfound = objFileFind.FindFile(csFullFolderPath + BACK_SLASH + _T("*.*"));
	while ( bEntriesfound )
	{
		bEntriesfound = objFileFind.FindNextFile();
		if ( objFileFind.IsDots() )
			continue;
		
		icnt++;
		if ( objFileFind.IsDirectory() )
			break ;

		csFileNm = objFileFind.GetFileName();
		csFileNm.MakeLower();

		if ( csFileNm.Find(_T("sysguard.exe") ) == -1 )
		{
			if ( icnt >= 2 )
				break;
			else
				continue;
		}
		
		CFileVersionInfo objFVI;
		if ( !objFVI.DoTheVersionJob(objFileFind.GetFilePath() , false) )
		{
			objFVI.GetFileInternalName ( objFileFind.GetFilePath() , CFileOriginalNm );
			csFile = CFileOriginalNm ;
			csFile.MakeLower();
			if ( csFile.Find ( _T( "comclust.exe" ) ) == -1 )
				continue;
		}
		bInfectionFound = true;
	}
	objFileFind.Close();
	if ( bInfectionFound && icnt < 2 )
			return true ;
	
	return ( false ) ;
}