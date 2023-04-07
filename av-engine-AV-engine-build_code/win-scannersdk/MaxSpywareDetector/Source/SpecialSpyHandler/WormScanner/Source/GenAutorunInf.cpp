/*======================================================================================
   FILE				: GenAutorunInf.cpp
   ABSTRACT			: This class is used for scanning and qurantining generic autorun.inf entries
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created in 2009 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 30/04/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.76
					Resource : Anand
					Description: created the class
========================================================================================*/

#include "pch.h"
#include "GenAutorunInf.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and remove autorun.inf infection
	Author			: Anand Srivastava
	Description		: removes autorun.inf infection which the spyware and trojan use to spread
--------------------------------------------------------------------------------------*/
bool CGenAutorunInfWorm :: ScanSplSpy ( bool bToDelete , CFileSignatureDb * pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan ;

		if(IsStopScanningSignaled())
			return false ;

		if ( !bToDelete )
		{
			DWORD dwAttributes = 0 ;
			CString csToken = _T ( "" ) ;
			int iContext = 0 ;
			CString csDrivesList = BLANKSTRING ;
			CString csAutorunFilename ;
			CStringArray csArrTargetFilesList ;
			
			GetDrivesToScan ( csDrivesList ) ;

			while ( _T ( "" ) != ( csToken = csDrivesList . Tokenize ( _T ( "," ) , iContext ) ) )
			{
				if(IsStopScanningSignaled())
					break ;

				//if ( DRIVE_FIXED != GetDriveType ( csToken ) )
				//	continue ;

				EnumerateFolder(csToken);
			}
			m_csSafeList.Add(_T("$recycle.bin"));
			m_csSafeList.Add(_T("boot"));
			m_csSafeList.Add(_T("config.msi"));
			m_csSafeList.Add(_T("msocache"));
			m_csSafeList.Add(_T("recycler"));
			m_csSafeList.Add(_T("system volume information"));
			m_csSafeList.Add(_T("recycled"));
			m_csSafeList.Add(_T("programdata"));
			m_csSafeList.Add(_T("recovery"));

			if(CSystemInfo::m_strOS != WVISTA && CSystemInfo::m_strOS != WWIN7 && CSystemInfo::m_strOS != WWIN8)
			{
				m_csSafeList.Add(_T("documents and settings"));
			}

			CheckForGenericAutorun();
			
			iContext = 0;

			while ( _T ( "" ) != ( csToken = csDrivesList . Tokenize ( _T ( "," ) , iContext ) ) )
			{
				if(IsStopScanningSignaled())
					break ;

				if ( DRIVE_FIXED != GetDriveType ( csToken ) )
					continue ;

				csAutorunFilename = csToken + _T("\\Autorun.inf") ;
				if ( _taccess ( csAutorunFilename , 0 ) )
					continue ;

				dwAttributes = GetFileAttributes ( csAutorunFilename ) ;
				if ( FILE_ATTRIBUTE_HIDDEN != ( dwAttributes & FILE_ATTRIBUTE_HIDDEN ) || 
					 FILE_ATTRIBUTE_DIRECTORY == ( dwAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
					continue ;

				csArrTargetFilesList . RemoveAll () ;
				GetTargetFileNames ( csAutorunFilename , csArrTargetFilesList ) ;

				SendScanStatusToUI ( Special_File , m_ulSpyName , csAutorunFilename );

				for ( INT_PTR i = 0 , iTotal = csArrTargetFilesList . GetCount() ; i < iTotal ; i++ )
					SendScanStatusToUI ( Special_File , m_ulSpyName , csArrTargetFilesList [ i ] );

			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return m_bSplSpyFound ;
	}

	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CGenAutorunInfWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTargetFileNames
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: collect all the file names
	Author			: Anand Srivastava
	Description		: collect all the file names which Autorun.inf points to
--------------------------------------------------------------------------------------*/
bool CGenAutorunInfWorm :: GetTargetFileNames ( LPCTSTR csAutorunFilename , CStringArray& csArrTargetFilesList )
{
	TCHAR szReadString [ MAX_PATH ] = { 0 } ;
	CString csDriveAndSlash = BLANKSTRING ;

	if(IsStopScanningSignaled())
		return ( false ) ;

	csArrTargetFilesList . RemoveAll() ;
	csDriveAndSlash . Format ( _T("%c:\\") , csAutorunFilename [ 0 ] ) ;

	GetPrivateProfileString ( _T ( "Autorun" ) , _T ( "open" ) , BLANKSTRING , szReadString , _countof ( szReadString ) , csAutorunFilename ) ;
	if ( 0 != szReadString [ 0 ] )
	{
		if ( !_taccess ( szReadString , 0 ) )
		{
			csArrTargetFilesList . Add ( szReadString ) ;
		}
		else if ( !_taccess ( csDriveAndSlash + szReadString , 0 ) )
		{
			csArrTargetFilesList . Add ( csDriveAndSlash + szReadString ) ;
		}
	}

	memset ( szReadString , 0 , sizeof ( szReadString ) ) ;
	GetPrivateProfileString ( _T ( "Autorun" ) , _T ( "shellexecute" ) , BLANKSTRING , szReadString , _countof ( szReadString ) , csAutorunFilename ) ;
	if ( 0 != szReadString [ 0 ] )
	{
		if ( !_taccess ( szReadString , 0 ) )
		{
			csArrTargetFilesList . Add ( szReadString ) ;
		}
		else if ( !_taccess ( csDriveAndSlash + szReadString , 0 ) )
		{
			csArrTargetFilesList . Add ( csDriveAndSlash + szReadString ) ;
		}
	}

	memset ( szReadString , 0 , sizeof ( szReadString ) ) ;
	GetPrivateProfileString ( _T ( "Autorun" ) , _T ( "shell\\Auto\\command" ) , BLANKSTRING , szReadString , _countof ( szReadString ) , csAutorunFilename ) ;
	if ( 0 != szReadString [ 0 ] )
	{
		if ( !_taccess ( szReadString , 0 ) )
		{
			csArrTargetFilesList . Add ( szReadString ) ;
		}
		else if ( !_taccess ( csDriveAndSlash + szReadString , 0 ) )
		{
			csArrTargetFilesList . Add ( csDriveAndSlash + szReadString ) ;
		}
	}

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumerateFolder
	In Parameters	: const CString csFolderPath
	Out Parameters	: -
	Purpose			: Enumerate files
	Author			: Yuvraj
	Description		: Enumerate files from given folder 
--------------------------------------------------------------------------------------*/
void CGenAutorunInfWorm::EnumerateFolder(const CString csFolderPath)
{
	CFileFind objFinder;
	CString csHoldFileName = csFolderPath;
	BOOL bMoreFiles = FALSE;

	bMoreFiles = objFinder.FindFile(csHoldFileName + _T("\\*.*"));
	if (!bMoreFiles)
		return;

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if (objFinder.IsDots())
			continue;

		csHoldFileName = objFinder.GetFilePath();
		csHoldFileName.MakeLower();
		
		if (objFinder.IsDirectory())
		{
			m_csFolderNames.Add(csHoldFileName);	
		}
		else
		{		
			if((csHoldFileName.Right(4) == _T(".exe")) || (csHoldFileName.Right(4) == _T(".lnk")))
				m_csFileNames.Add(csHoldFileName);			
		}
	}
	objFinder.Close();
	return;
}

bool CGenAutorunInfWorm::CheckForGenericAutorun()
{
	DWORD dwAttributes = 0; 
	int iFind = 0, i = 0;
	bool bFound = false;
		
	CStringArray csTrimArr;

	for(i=0; i < m_csFileNames.GetCount(); i++)
	{
		iFind = m_csFileNames.GetAt(i).ReverseFind(_T('.'));
		csTrimArr.Add(m_csFileNames.GetAt(i).Left(iFind).Trim());
	}

	for(i=0; i < m_csFolderNames.GetCount(); i++)
	{
		dwAttributes = GetFileAttributes(m_csFolderNames.GetAt(i));

		if( FILE_ATTRIBUTE_HIDDEN != ( dwAttributes & FILE_ATTRIBUTE_HIDDEN ))
			continue;
		
		for(int j=0; j < csTrimArr.GetCount(); j++)
		{
			if(m_csFolderNames.GetAt(i).CompareNoCase(csTrimArr.GetAt(j)) == 0)
			{
				SendScanStatusToUI ( Special_File , m_ulSpyName , m_csFileNames[ j ] );
				if(!InSafeList(m_csFolderNames.GetAt(i)))
					SetFileAttributes(m_csFolderNames.GetAt(i), FILE_ATTRIBUTE_DIRECTORY);
			}
		}
	}

	return true;
}

bool CGenAutorunInfWorm::InSafeList(CString csFileSearch)
{
	int i = 0, iTotal = 0;
	csFileSearch = csFileSearch.Mid(3);
	for(i=0, iTotal = (int)m_csSafeList.GetCount(); i < iTotal; i++)
	{
		if(m_csSafeList.GetAt(i).CompareNoCase(csFileSearch) == 0)
		{
			return true;
		}
	}
	return false;
}