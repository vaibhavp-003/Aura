/*====================================================================================
   FILE				: InfectedFiles.cpp
   ABSTRACT			: This class is used for scanning and qurantining general spyware
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Darshan
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
#include "infectedfiles.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforInfectedFiles
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleans
	Author			: 
	Description		: Searches for all the keyword list and returns true in 'bFound'
					  if all of them were found
--------------------------------------------------------------------------------------*/
bool CInfectedFiles::ScanSplSpy(bool bIsDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		CFileFind objFile;
		CString csInfectedFileName;
		CStringArray csArrLocations ;

		csArrLocations . Add ( CSystemInfo::m_strSysDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherSysDir ) ;

		for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
		{
			csInfectedFileName = csArrLocations [ i ] + _T("\\wininet.dll");
			if( HandleInfectedFile( csInfectedFileName, _T("wininet.dll"), "OLEADM" , "OLEEXT", bIsDelete))
			{
				if( FindReportKillOnRestart( csArrLocations [ i ] + _T("\\oleadm.dll"), 3760, bIsDelete))
					m_bSplSpyFound = true;

				if( FindReportKillOnRestart( csArrLocations [ i ] + _T("\\oleext.dll"), 3760, bIsDelete))
					m_bSplSpyFound = true;

				if( FindReportKillOnRestart( csArrLocations [ i ] + _T("\\oleext32.dll"), 3760, bIsDelete))
					m_bSplSpyFound = true;
			}
		}

		m_bSplSpyFound = bIsDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format ( _T("Exception caught in CInfectedFiles::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: HandleInfectedFile
	In Parameters	: const char *, const char *, const char *, const char *, bool 
	Out Parameters	: 
	Purpose			: Checks and replaces by clean version
	Author			: 
	Description		: checks for key words in files, if found replace them with clean version
--------------------------------------------------------------------------------------*/
bool CInfectedFiles::HandleInfectedFile(LPCTSTR sInfectedFileName, LPCTSTR sFileName, const char *sInfectionText1, const char *sInfectionText2, bool bIsDelete)
{
	try
	{
		if(IsStopScanningSignaled())
			return false;

		int iRetVal = 0;
		TCHAR sTempFile[MAX_PATH] = { 0 } ;
		CArray<CStringA,CStringA> objStrings1 ;
		CArray<CStringA,CStringA> objStrings2 ;
		
		objStrings1 . Add ( sInfectionText1 ) ;
		objStrings2 . Add ( sInfectionText2 ) ;

		if ( SearchStringsInFile ( sInfectedFileName , objStrings1 ) || SearchStringsInFile ( sInfectedFileName , objStrings2 ) )
			 iRetVal = LOOKIN_TEXT_FOUND_IN_FILE ;

		if(iRetVal == LOOKIN_TEXT_FOUND_IN_FILE)
		{
			TCHAR sGenuineFileName[MAX_PATH];
			if(!GetGenuineFile(sFileName, sGenuineFileName,_countof(sGenuineFileName)))
			{
				return ( false ) ;
			}

			if(bIsDelete)
			{
				CFileOperation	objFileOperation;
			
				_tcscpy_s ( sTempFile , _countof ( sTempFile ) , sInfectedFileName ) ;
				_tcscat_s ( sTempFile , _countof ( sTempFile ) , _T(".infected") ) ;
				
				objFileOperation . DeleteThisFile ( sTempFile ) ;
				MoveFile(sInfectedFileName, sTempFile);
				CopyFile(sGenuineFileName, sInfectedFileName, false);
				
				if(!objFileOperation.DeleteThisFile(sTempFile))
				{
					//delete infected file on restart
					_tcscpy_s ( sTempFile, _countof(sTempFile) , _T("Trojan.Spyaxe^"));
					_tcscat_s ( sTempFile, _countof(sTempFile) , sInfectedFileName);
					_tcscat_s ( sTempFile, _countof(sTempFile) , _T(".infected"));
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, sTempFile);
				}
			}
			return ( true ) ;
		}
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CInfectedFiles::HandleInfectedFile, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
