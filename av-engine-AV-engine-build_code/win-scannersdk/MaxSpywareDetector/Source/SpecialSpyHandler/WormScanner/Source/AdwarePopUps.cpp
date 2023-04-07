 /*====================================================================================
   FILE				: AdwarePopups.cpp
   ABSTRACT			: This class contains functions for scanning and fixing spyware Adware Popups
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
#include <fcntl.h>
#include <sys/stat.h>
#include "adwarepopups.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForAdwarePopups
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: checks and removes adware popups
	Author			: Anand
	Description		: this function checks for Popups which come
					  using the desktop setting of html page
					  //version: 16.4
					  //resource: Anand
					  also added .htm? file searching code in PFDIR and
					  looks for a .js file where html file is found.
--------------------------------------------------------------------------------------*/
bool CAdwarePopUps :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		CStringArray csArrSubKeys ;
		CString csFileName ;
		bool bFound = false ;

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;

			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			m_objReg.EnumSubKeys(csUserKey + _T("\\") + DESKTOP_COMPONENTS_PATH, csArrSubKeys, HKEY_USERS);

			// enumerate all the keys to be checked for any entry of popups infection
			int nSubKeys = (int)csArrSubKeys.GetCount();
			for ( int i = 0; i < nSubKeys; i++ )
			{
				if(IsStopScanningSignaled())
					break;

				if ( csArrSubKeys[ i ].GetLength() == 0)
					continue ;

				bFound = false ;
				// read the data in 'source' under this key
				m_objReg.Get ( csUserKey + BACK_SLASH + DESKTOP_COMPONENTS_PATH + BACK_SLASH + csArrSubKeys[i], _T("Source"), csFileName, HKEY_USERS);
				if ( IsThisPopupsFile ( csFileName ) )
				{
					bFound = true ;
					if(FindReportRegKey( csUserKey + BACK_SLASH + DESKTOP_COMPONENTS_PATH + BACK_SLASH + csArrSubKeys[i], m_ulSpyName , HKEY_USERS, bToDelete, true))
						m_bSplSpyFound = true;
				}

				if ( bFound )
				{
					int iLastSlash = csFileName . ReverseFind ( _T('\\') ) ;
					if ( -1 != iLastSlash )
						m_bSplSpyFound = SearchForPopupAdwareFile ( csFileName . Left ( iLastSlash ) ) ? true : m_bSplSpyFound ;
				}

				csFileName.Empty();
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
		csErr.Format( _T("Exception caught in CAdwarePopUps::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsThisPopupsFile
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: checks files for popups
	Author			: Anand
	Description		: this function determines popups infection file
--------------------------------------------------------------------------------------*/
bool CAdwarePopUps :: IsThisPopupsFile ( const CString& csFileName )
{
	bool bInfected = true ;
	int hFile = -1 , iRetValue = 0 ;
	char * Set1 [] =
	{
		"\nfunction process" ,
		"\nfunction start"
	} ;

//Version: 16.8
//Resource: Anand
// earlier ti was checking if <html> tag is absent

//Version: 2.5.0.1
//Resource: Anand
//Description: complex spy separated from product and
//			   false positive fixed by removing scan for set2

/*	char * Set2 [] = 
	{
		"write(unescape" ,
		"write (unescape" ,
		"write ( unescape" ,
		"write( unescape" 
	} ;
*/

	//Resource: Darshan
	//Description: return if scanning is stopped
	if(IsStopScanningSignaled())
		return false;

	iRetValue = _tsopen_s ( &hFile , csFileName , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
	if ( 0 != iRetValue || hFile == -1 )
		return ( false ) ;

	// search for all the strings in Set1, if all found, file is infected
	for ( int i = 0 ; i < sizeof ( Set1 ) / sizeof(Set1 [ 0 ]) && bInfected ; i++ )
	{
		bInfected = false ;
		//Resource: Darshan
		//Description: return if scanning is stopped
		if(IsStopScanningSignaled())
			break;
		SearchString ( hFile , Set1 [ i ] , &bInfected ) ;
	}

	// search for all the strings in Set2, if any of them is found, file is infected
	//for ( int i = 0 ; i < sizeof ( Set2 ) / sizeof (Set2 [ 0 ]) && !bInfected ; i++ )
	//	SearchString ( hFile , Set2 [ i ] , &bInfected ) ;

	//CloseHandle ( hFile ) ;
	_close ( hFile ) ;
	return ( bInfected ) ;
}


/*-------------------------------------------------------------------------------------
	Function		: SearchForPopupAdwareFile
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: search for adware popuper files
	Author			: Anand
	Description		: This function searches popup adware html and js files in PFDIR
--------------------------------------------------------------------------------------*/
bool CAdwarePopUps :: SearchForPopupAdwareFile ( CString csSearchFolder )
{
	try
	{
		BOOL	bMoreFiles = FALSE ;
		bool	bInfectedFileFound = false ;
		CFileFind oFinder ;
	
		bMoreFiles = oFinder.FindFile(csSearchFolder + _T("\\*.*") );
		while ( bMoreFiles )
		{
			//Resource: Darshan
			//Description: return if scanning is stopped
			if(IsStopScanningSignaled())
				break;

			bMoreFiles = oFinder.FindNextFile() ;
			if ( oFinder.IsDots() )
				continue ;

			if ( oFinder.IsDirectory() )
			{
				if ( SearchForPopupAdwareFile ( oFinder.GetFilePath()))
					bInfectedFileFound = true ;
			}
			else
			{
				
				if ( !IsExtensionHTMLOrHTM ( oFinder.GetFileName() ) )
					continue ;

				
				if ( IsThisPopupsFile ( oFinder.GetFilePath() ) )
				{
					bInfectedFileFound = true ;
					SendScanStatusToUI ( Special_File, m_ulSpyName , oFinder.GetFilePath() ) ;

					int hFile = -1 ;
					bool bFound = false ;
					CFileFind objFinder ;
					BOOL bSearch = FALSE ;
					bSearch = objFinder . FindFile ( csSearchFolder + _T("\\*.js") ) ;
					while ( bSearch )
					{
						//Resource: Darshan
						//Description: return if scanning is stopped
						if(IsStopScanningSignaled())
							break;

						bSearch = objFinder.FindNextFile() ;
						if ( objFinder.IsDirectory() || objFinder.IsDots() )
							continue ;

						int iRetValue = _tsopen_s ( &hFile , objFinder.GetFilePath() , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
						if ( -1 != hFile )
						{
							char * lpszFilenameToSearch = NULL ;
							char szTmpName [ MAX_PATH ] = { 0 } ;
#if ( defined UNICDOE || defined _UNICODE )
							sprintf_s ( szTmpName , sizeof ( szTmpName ) , "%S" , static_cast<LPCTSTR>(oFinder.GetFileName()) ) ;
							lpszFilenameToSearch = szTmpName ;
#else
							lpszFilenameToSearch = oFinder.GetFileName() ;
#endif
							SearchString ( hFile , lpszFilenameToSearch , &bFound ) ;
							_close ( hFile ) ;
							if ( bFound )
								SendScanStatusToUI ( Special_File, m_ulSpyName , objFinder . GetFilePath() ) ;
						}
					}
					objFinder . Close() ;
				}
			}
		}
		oFinder . Close() ;
	}

	catch(...)
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in  CAdwarePopUps :: SearchForPopupAdwareFile, Error: %d") , GetLastError() ) ;
		AddLogEntry( csErr , 0, 0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsExtensionHTMLOrHTM
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: checks the extension of the filename
	Author			: Anand
	Description		: returns true if the extension of the file is either html or htm
--------------------------------------------------------------------------------------*/
bool CAdwarePopUps :: IsExtensionHTMLOrHTM ( CString csFileName )
{
	//Version : 19.0.0.013
	//Resource: dipali
	//change in extension finding code
	csFileName.MakeLower();
	if(csFileName.Right(4) == _T(".htm") || csFileName.Right(5) == _T(".html") )
		return ( true );
	return ( false ) ;
}
