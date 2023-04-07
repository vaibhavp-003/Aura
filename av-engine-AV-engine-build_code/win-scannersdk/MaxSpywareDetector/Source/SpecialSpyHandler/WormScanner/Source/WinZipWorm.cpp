/*====================================================================================
   FILE				: WinZipWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinZip
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
#include "winzipworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForWinZip
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove winzip
	Author			: Anand
	Description		: this function checks if winzip virus has made any scheduler entries
					  and sends the scheduler files to the frontend if found any
					  and also replaces infected mswinsck.ocx with fresh one from DllCache
					  if there is no fresh copy present on the machine, infected file is deleted
--------------------------------------------------------------------------------------*/
bool CWinZipWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		CString		csWinSckFile;
		CString		csDllCacheWSck;
		
		if ( !bToDelete )
		{
			CFileFind objFile;
			CStringArray csArrLocations ;

			csArrLocations . Add ( CSystemInfo::m_strSysDir ) ;
			if ( m_bScanOtherLocations )
				csArrLocations . Add ( m_csOtherSysDir ) ;

			for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
			{
				//TODO: change md5 to new format

				//// make signature of mswinsck.ocx file
				//CString csSignature ;
				//csWinSckFile	=	csArrLocations [ i ] + _T("\\MSWINSCK.OCX") ;
				//csSignature		=	m_pFileSigMan->GetSignature(csWinSckFile);
				//csSignature.MakeUpper();

				//// check if the file is infected
				//if ( csSignature == _T("16D5D7AE461D2CB51EF0085400FF7C5A") )
				//{
				//	m_bSplSpyFound = true ;

				//	// check if the fresh copy is available in DllCache
				//	csDllCacheWSck = csArrLocations [ i ] + _T("\\DllCache\\MSWINSCK.OCX") ;
				//	if ( _taccess_s ( csDllCacheWSck , 0 ) == 0 )
				//		SendScanStatusToUI ( Special_File , m_ulSpyName , _T("0^") + csWinSckFile  ); 	//UI will not delete the file
				//	else
				//		SendScanStatusToUI (Special_File ,  m_ulSpyName , csWinSckFile ) ;
				//}
			}

			// now search and remove any schedulers added by winzip
			CString		csFileName ;
			CString		csSearchString	=	m_objSysInfo.m_strWinDir + _T("\\Tasks\\*.job") ;
			
			BOOL bLoop = objFile.FindFile ( csSearchString ) ;
			if ( !bLoop )
				return m_bSplSpyFound;
						
			while ( bLoop )
			{
				if(IsStopScanningSignaled())
					break ;

				bLoop = objFile.FindNextFile() ;
				if ( objFile.IsDirectory() || objFile.IsDots() )
					continue ;

				csFileName = objFile.GetFilePath() ;
				if ( csFileName.IsEmpty() )
					continue ;

				// check if this file is a Winzip scheduler file
				if ( IsWinZipScheduler ( csFileName ) )
				{
					SendScanStatusToUI ( Special_File , m_ulSpyName , csFileName ) ;
					m_bSplSpyFound = true ;
				}
			}
			objFile.Close() ;
		}
		else
		{
			// replace the fresh Dllcache copy on the infected one
			if ( !_taccess_s ( csDllCacheWSck , 0 ) )
				MoveFileEx ( csDllCacheWSck , csWinSckFile , MOVEFILE_DELAY_UNTIL_REBOOT|MOVEFILE_REPLACE_EXISTING ) ;
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
		csErr.Format( _T("Exception caught in CWinZipWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsWinZipScheduler
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: check file for winzip helper file
	Author			: Anand
	Description		: This function determines whether a given file is winzip scheduler file
--------------------------------------------------------------------------------------*/
bool CWinZipWorm::IsWinZipScheduler ( CString csFileName)
{
	try
	{
		bool bFound = false ;
		HANDLE hFile = 0 ;
		DWORD dwFileNameLoc = 0x46 , FileNameLen = 0 , BytesRead = 0 ;
		unsigned char ExecFileName [ MAX_PATH ] = { 0 } ;

		// open file
		hFile	=	CreateFile ( csFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if ( hFile == INVALID_HANDLE_VALUE )
			return ( bFound ) ;

		// set to the filename size reading offset and read filename
		SetFilePointer ( hFile, dwFileNameLoc, 0, FILE_BEGIN);
		if ( FALSE == ReadFile ( hFile, &FileNameLen, 2, &BytesRead, 0) )
		{
			CloseHandle ( hFile );
			return false ;
		}

		if ( FileNameLen * 2 >= _countof ( ExecFileName ) )
		{
			CloseHandle ( hFile );
			return false ;
		}

		if ( FALSE == ReadFile ( hFile, ExecFileName, FileNameLen * 2, &BytesRead, 0) )
		{
			CloseHandle ( hFile );
			return false ; 
		}

		// UNICODE support added, hence no need to convert to ansi name
		// convert unicode filename to ascii
		//for ( DWORD i = 0 ; i < FileNameLen * 2 ; i++ )
		//	ExecFileName [ i ] = ExecFileName [ i * 2 ] ;

		CloseHandle ( hFile ) ;

		// make signature of the infected file of scheduler
		BYTE bMD5Signature[16] = {0};
		const BYTE MD5_WINZIP[16] = {0x1C,0x66,0x90,0x4E,0xCB,0x84,0x6D,0xA5,0xB1,0xFB,0x20,0x72,0xF9,0xEA,0x6E,0x0E};
		if(m_pFileSigMan->GetMD5Signature(CString(ExecFileName), bMD5Signature))
		{
			// check if the file is infected winzip file
			if(!memcmp(bMD5Signature, MD5_WINZIP, 16))
				return true;
		}
		return false;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinZipWorm::IsWinZipScheduler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
