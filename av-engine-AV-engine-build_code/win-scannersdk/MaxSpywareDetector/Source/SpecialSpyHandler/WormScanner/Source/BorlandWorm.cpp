/*=============================================================================
   FILE				: BorlandWorm.Cpp
   ABSTRACT			: Inplementation of class BorlandWorm
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			:
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: DD/Month/YYYY
   NOTES			:
   VERSION HISTORY	: 
			Date	: 18 June 2007
			Version : 2.5.0.2	
			Resource: Shweta
			Description: Added Code for random folder and files in PFDIR 

			version: 2.5.0.23
			Resource : Anand
			Description: Ported to VS2005 with Unicode and X64 bit Compatability
=============================================================================*/

#include "pch.h"
#include "borlandworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool ,CFileSignatureDb*
	Out Parameters	: bool
	Purpose			: scanning start point
	Author			: Shweta
	Description		: start scanning
	Version			: 2.5.0.2
--------------------------------------------------------------------------------------*/
bool CBorlandWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		if(!bToDelete)
		{
			ChangePermission( CString(SERVICES_MAIN_KEY) + CString(_T("\\Albus")), HKEY_LOCAL_MACHINE);
		}
		else
		{
			CStringArray csArrLocations ;

			csArrLocations.Add ( CSystemInfo::m_strProgramFilesDir ) ;
			if ( m_bScanOtherLocations )
				csArrLocations.Add( m_csOtherPFDir ) ;

			for ( int i = 0 ; i < (int)csArrLocations.GetCount() ; i++ )
			{
				SetFileAttributes ( csArrLocations [ i ] + _T("\\mmsassist"), FILE_ATTRIBUTE_ARCHIVE); 
				AddInRestartDeleteList(RD_FOLDER, m_ulSpyName, csArrLocations [ i ] + _T("\\mmsassist"));
			}
		}

		if ( CheckAndRemoveDriver ( m_ulSpyName , _T("ALBUS"), m_objSysInfo.m_strSysDir + _T("\\Drivers\\ALBUS.sys"), m_csArrDelKeys, bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("ALBUS"), m_csOtherSysDir + _T("\\Drivers\\ALBUS.sys"), m_csArrDelKeys, bToDelete))
				m_bSplSpyFound = true;
		}

		//release  :2.5.0.2
		//resource :Shweta
		//description: fixed random folder in pfdir
		if(bToDelete)
		{
			for (int i = 0 ; i < m_csArrFiles2Delete.GetCount() ; i++)
			{
				MoveFileEx ( m_csArrFiles2Delete.GetAt(i),NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
			}
		}
		else
		{
			m_csArrFiles2Delete.RemoveAll();
			if ( CheckforPFDirRandomEntry() )
			{
				m_bSplSpyFound = true;
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CBorlandWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckforPFDirRandomEntry
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: checks Program files directory
	Author			: Shweta
	Description		: Checks for Pfdir random entries and calls CheckifSpyware.
	Version			: 2.5.0.2
--------------------------------------------------------------------------------------*/
bool CBorlandWorm::CheckforPFDirRandomEntry()
{
	CFileFind objFileFind ;
	BOOL bRet = false ;
	bool bFolderFound = false ;
	CStringArray csArrLocations ;

	csArrLocations.Add ( CSystemInfo::m_strProgramFilesDir ) ;
	if ( m_bScanOtherLocations )
		csArrLocations.Add ( m_csOtherPFDir ) ;

	for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
	{
		bRet = objFileFind . FindFile ( CSystemInfo::m_strProgramFilesDir + _T("\\*.*") ) ;
		if ( !bRet )
			continue ;

		while ( bRet )
		{
			bRet = objFileFind.FindNextFile();
			if ( objFileFind.IsDots() )
				continue;

			if ( !objFileFind.IsDirectory() )
				continue ;

			if ( !_tcsnicmp(objFileFind.GetFilePath(), CSystemInfo::m_strAppPath, objFileFind.GetFilePath().GetLength()))
				continue ;

			if ( CheckIfSpywareFolder(objFileFind.GetFilePath()))
			{
				bFolderFound = true ;
				RemoveFolders ( objFileFind . GetFilePath() , m_ulSpyName , false ) ;
			}
		}
		objFileFind . Close() ;
	}
	return ( bFolderFound ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfSpywareFolder
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: checks particular PFDIR folder
	Author			: Shweta
	Description		: Checks for dll in the sub directory of PFDIR if the keyword is found 
					  in more than 2 dll that folder is Spyware folder
	Version			: 2.5.0.2
--------------------------------------------------------------------------------------*/
bool CBorlandWorm::CheckIfSpywareFolder(const CString& csFolderPath)
{
	CFileFind objFFinddll;
	BOOL bnewRet =  false;
	bool bstatus = false;
    CArray<CStringA,CStringA> csArr ;
	int icnt = 0;

	csArr . Add ( "borlander.cn" ) ;
	bnewRet = objFFinddll . FindFile ( csFolderPath + _T("\\*.dll") ) ;
	if ( !bnewRet )
		return ( false ) ;

	while(bnewRet)
	{
		bnewRet = objFFinddll.FindNextFile();
		if ( objFFinddll.IsDots() || objFFinddll.IsDirectory() )
			continue;

		if ( SearchStringsInFile ( objFFinddll.GetFilePath() , csArr ) )
		{
			icnt++ ;
			m_csArrFiles2Delete.Add(objFFinddll.GetFilePath());
		}

		bstatus = icnt >= 2 ;
	}

	objFFinddll . Close() ;
	return ( bstatus ) ;
}
