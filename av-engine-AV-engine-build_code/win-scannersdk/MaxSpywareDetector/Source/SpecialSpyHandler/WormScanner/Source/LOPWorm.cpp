/*====================================================================================
   FILE				: LOPWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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

					version: 2.5.0.47
					Resource : Anand
					Description: Fixed LOP folder for new variants
========================================================================================*/

#include "pch.h"
#include <io.h>
#include <fcntl.h>
#include <sys\stat.h>
#include "lopworm.h"
//#include <shfolder.h>
#include "StringFunctions.h"
#include "ExecuteProcess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForLOP
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for random entries of LOP
	Author			: Anand
	Description		: check for random files in user\aap data folder
--------------------------------------------------------------------------------------*/
bool CLOPWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		TCHAR szPath [ MAX_PATH ] = { 0 } ;

		// get user application data path
		SHGetFolderPath ( 0, CSIDL_APPDATA ,0 , 0, szPath);
		if ( 0 != szPath [ 0 ] )
		{
			_SearchFolderForRandomLOPEntries ( szPath, m_ulSpyName ) ;
			memset ( szPath, 0, sizeof( szPath ));
		}

		// get common user app data path
		SHGetFolderPath ( 0 , CSIDL_COMMON_APPDATA , 0 , 0 , szPath ) ;
		if ( 0 != szPath [ 0 ] )
			_SearchFolderForRandomLOPEntries ( szPath, m_ulSpyName) ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLOPWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}	
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: SearchFolderForRandomLOPEntries
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for random entries of LOP
	Author			: Anand
	Description		: check for random files in user\aap data folder
--------------------------------------------------------------------------------------*/
bool CLOPWorm :: _SearchFolderForRandomLOPEntries ( CString csSearchFolder, ULONG ulSpywareName)
{
	try
	{
		CFileFind objFinder ;
		BOOL bMoreFiles = TRUE ;

		if ( !objFinder.FindFile( csSearchFolder + _T("\\*.*") ) )
			return false;

		while ( bMoreFiles )
		{
			bMoreFiles = objFinder.FindNextFile() ;
			if ( objFinder.IsDots() || !objFinder.IsDirectory() )
				continue ;

			CString csFilePath = objFinder.GetFilePath();
			if ( _IsItLOPFolder ( csFilePath ) )
			{
				m_bSplSpyFound = true ;
				RemoveFolders ( csFilePath, ulSpywareName, false);
				_CheckLOPRunEntries( csFilePath.MakeLower());
				_IsLOPScheduler( csFilePath, ulSpywareName);
			}		
		}
		objFinder.Close() ;
		return true;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLOPWorm::_SearchFolderForRandomLOPEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);		
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsItLOPFolder
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: determine whether a given folder is LOP folder or not
	Author			: Anand
	Description		: check that all the exe files in the folder are LOP files
--------------------------------------------------------------------------------------*/
bool CLOPWorm :: _IsItLOPFolder ( CString csFolderName )
{
	try
	{
		int hFile = -1 ;
		CFileFind objFinder ;
		BOOL bMoreFiles = TRUE ;
		bool bFolderInfected = false , bStrFound = false ;
		unsigned char ucLOPSignature [] = 
		{
			0x0 , 0x0 , 0x33 , 0xC0 , 0x8A , 0x17 , 0x32 , 0x14 , 0x18 , 0x88 ,
			0x17 , 0x40 , 0x83 , 0xF8 , 0x05 , 0x7C , 0x02 , 0x33 , 0xC0 , 0x47 ,
			0xE2 , 0xEE 
		} ; 

		/*Remaining Common Strings
		)Ç‰À‰ù‰Æ‹¼$ 
		)×‰Ð‰ù‰Æ‹¼$ 
		)×‰ù‰Ö‰Çó¤ÇDLL 
		)Ï‰È‰ù‰Æ‹¼$ 
		)÷‰ù‰Çó¤ÇDLL 
		‰Þ‰Çó¤ÇDLL 
		$ÀÿÿÿÇ„$¼ÿÿÿ 
		ÿÿÿè‰„$ÌÿÿÿÇ„$Èÿÿÿ 
		‰Œ$ÌÿÿÿÇ„$Èÿÿÿ --In Use by this function
		‰”$ÌÿÿÿÇ„$Èÿÿÿ 
		‰¬$ÌÿÿÿÇ„$Èÿÿÿ 
		Ø‰„$ÌÿÿÿÇ„$Èÿÿÿ 
		Ù‰Œ$ÌÿÿÿÇ„$Èÿÿÿ 
		Ú‰”$ÌÿÿÿÇ„$Èÿÿÿ 
		$hýÿÿÇ„$dýÿÿ 
	*/
		unsigned char ucnextLOPSignature [] = 
		{
			0x89 , 0x8C , 0x24 , 0xCC , 0xFF , 0xFF , 0xFF , 0xC7 ,
			0x84 , 0x24 , 0xC8 , 0xFF , 0xFF , 0xFF
		} ;

		if ( !objFinder.FindFile( csFolderName + _T("\\*.exe") ) )
			return false ;

		while ( bMoreFiles )
		{
			bMoreFiles = objFinder.FindNextFile();
			if ( objFinder.IsDots() || objFinder.IsDirectory() )
				continue ;

			_tsopen_s ( &hFile , objFinder.GetFilePath(), _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
			if ( -1 != hFile )
			{
				bFolderInfected = false ;
				SearchString ( hFile, ucLOPSignature, sizeof ( ucLOPSignature ), &bFolderInfected ) ;
				if ( !bFolderInfected )
				{
					SearchString ( hFile, ucnextLOPSignature, sizeof( ucnextLOPSignature ), &bFolderInfected ) ;
				}

				_close ( hFile ) ;
				if ( bFolderInfected )
					break ;
			}
		}

		objFinder.Close() ;

		// if folder not infected check for this pattern
		// more than 50% should be exes and entry should be in Run
		if ( false == bFolderInfected )
		{
			bFolderInfected = _CheckPatternInFolder ( csFolderName , HKEY_LOCAL_MACHINE ) ;
			if ( false == bFolderInfected )
				bFolderInfected = _CheckPatternInFolder ( csFolderName , HKEY_USERS ) ;
		}

		return  ( bFolderInfected ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CLOPWorm::_IsItLOPFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

//Version :19.0.0.33
/*-------------------------------------------------------------------------------------
Function		: _CheckLOPRunEntries
In Parameters	: const CString&
Out Parameters	: 
Purpose			: check for Run Entries of LOP
Author			: Shweta
Description		: Check for Folder Entry in RUN
--------------------------------------------------------------------------------------*/
bool CLOPWorm :: _CheckLOPRunEntries ( const CString& csFolder )
{
	TCHAR szLongName [ MAX_PATH ] = { 0 } ;
	TCHAR szShortName [ MAX_PATH ] = { 0 } ;

	GetShortPathName ( csFolder , szShortName , _countof ( szShortName ) ) ;
	_tcscpy_s ( szLongName , _countof ( szLongName ) , csFolder ) ;
	_tcslwr_s ( szShortName , _countof ( szShortName ) ) ;
	_tcslwr_s ( szLongName , _countof ( szLongName ) ) ;

	SearchStringInRunKeyData ( m_ulSpyName , szShortName , CString() , CString() , HKEY_LOCAL_MACHINE ) ;
	SearchStringInRunKeyData ( m_ulSpyName , szLongName , CString() , CString() , HKEY_LOCAL_MACHINE ) ;

	SearchStringInRunKeyData ( m_ulSpyName , szShortName , CString() , CString() , HKEY_USERS ) ;
	SearchStringInRunKeyData ( m_ulSpyName , szLongName , CString() , CString() , HKEY_USERS ) ;

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
Function		: CheckForScheduler 
In Parameters	: const CString& , const CString&
Out Parameters	: void
Purpose			: check for Schedular of LOP
Author			: Shweta
Description		: Check for Schedular OF Lop
--------------------------------------------------------------------------------------*/
void CLOPWorm::_IsLOPScheduler ( const CString& csFolder , ULONG ulSpywareName )
{
	BOOL bFound = false, bFileFlag = false;
	HANDLE hFile = 0 ;
	DWORD dwFileNameLoc = 0x46 , FileNameLen = 0 , BytesRead = 0 ;
	unsigned char ExecFileName [ MAX_PATH ] = { 0 } ;
	CString csFullFileName , csSearchPath ;
	CFileFind objFile;
	bool bFilenameFound = false ;

	TCHAR cshortname[MAX_PATH], clongname[MAX_PATH];
	_tcscpy_s ( cshortname, _countof ( cshortname ) , csFolder);
	GetShortPathName(cshortname,clongname,MAX_PATH);

	csSearchPath	=	CSystemInfo::m_strWinDir + _T("\\Tasks\\*.Job") ;
	bFileFlag = objFile.FindFile( csSearchPath ) ;
    while ( bFileFlag )
	{
		bFilenameFound = false ;

		bFileFlag = objFile.FindNextFile() ;
		if ( objFile.IsDots() || objFile.IsDirectory() )
			continue ;

		csFullFileName = objFile.GetFilePath() ;
		FileNameLen = csFolder.GetLength() ;
		
		// open file
		hFile = CreateFile ( csFullFileName , GENERIC_READ , FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if ( hFile == INVALID_HANDLE_VALUE )
			continue ;

		if ( dwFileNameLoc > GetFileSize(hFile,NULL))
		{
			CloseHandle(hFile) ;
			continue ;
		}

		// set to the filename size reading offset and read filename
		SetFilePointer ( hFile , dwFileNameLoc , 0 , FILE_BEGIN );
		if ( FALSE == ReadFile ( hFile, &FileNameLen, 2, &BytesRead, 0 ) )
		{
			CloseHandle ( hFile ) ;
			continue ;	
		}

		if ( FileNameLen * 2 >= _countof ( ExecFileName ) )
		{
			CloseHandle ( hFile ) ;
			continue;
		}

		if ( FALSE == ReadFile ( hFile , ExecFileName , FileNameLen * 2 , &BytesRead , 0 ) )
		{
			CloseHandle ( hFile ) ;
			continue;
		}

		CloseHandle ( hFile ) ;

#if !defined _UNICODE
		// convert Unicode filename to Ascii
		for ( DWORD i = 0 ; i < FileNameLen * 2 ; i++ )
			ExecFileName[ i ] = ExecFileName [ i * 2 ] ;
#endif

		CString csFoundName = ((TCHAR*)(ExecFileName)) ;
		CString csFinalFolder = clongname ;

		csFoundName.MakeLower();
		csFinalFolder.MakeLower();

		if ( csFoundName.Find ( csFinalFolder , 0 ) != -1 )
            SendScanStatusToUI ( Special_File, ulSpywareName , objFile.GetFilePath()  ) ;
	}
	objFile . Close() ;
}

/*-------------------------------------------------------------------------------------
Function		: _CheckPatternInFolder
In Parameters	: CString
Out Parameters	: bool
Purpose			: check pattern
Author			: Anand
Description		: check for a pattern in folder to scan
--------------------------------------------------------------------------------------*/
bool CLOPWorm :: _CheckPatternInFolder ( CString csFolderName , HKEY hHive )
{
	TCHAR szShortName [ MAX_PATH ] = { 0 } ;
	CStringArray csArrValue , csArrData ;
	CFileFind objFinder ;
	BOOL bFound = FALSE ;
	int iExeFileCount = 0 ;
	int iNonExeFileCount = 0 ;
	CString csExt ;
	bool bPatternFound = false ;
	CString csSid;
	CExecuteProcess objExeProc;

	csFolderName . MakeLower() ;
	GetShortPathName ( csFolderName , szShortName , _countof ( szShortName ) ) ;
	_tcslwr_s ( szShortName , _countof ( szShortName ) ) ;

	csSid = objExeProc.GetCurrentUserSid();

	// search folder name in HKLM
	if ( hHive == HKEY_USERS )
		m_objReg . QueryDataValue(csSid + BACK_SLASH + RUN_REG_PATH , csArrValue , csArrData , hHive ) ;
	else
		m_objReg . QueryDataValue( RUN_REG_PATH , csArrValue , csArrData , hHive ) ;

	for ( int i = 0 ; i < csArrValue . GetCount() ; i++ )
	{
		csArrData [ i ] . MakeLower() ;
		if ( ( -1 == csArrData [ i ] . Find ( csFolderName ) ) && ( -1 == csArrData [ i ] . Find ( szShortName ) ) )
			continue ;

		bFound = objFinder . FindFile ( csFolderName + _T ( "\\*" ) ) ;
		if ( bFound )
		{
			while ( bFound )
			{
				bFound = objFinder . FindNextFile() ;
				if ( objFinder .IsDots() || objFinder .IsDirectory() )
					continue ;

				csExt = objFinder . GetFilePath() . Right ( 4 ) ;
				csExt . MakeLower() ;

				if ( csExt == _T ( ".exe" ) )
					iExeFileCount++ ;
				else
					iNonExeFileCount++ ;
			}

			objFinder . Close() ;
		}
	}

	if ( ( iNonExeFileCount * 2 ) < iExeFileCount )
		bPatternFound = true ;

	return ( bPatternFound ) ;
}
