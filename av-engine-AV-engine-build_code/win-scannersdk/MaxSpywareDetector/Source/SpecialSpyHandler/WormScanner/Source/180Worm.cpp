/*======================================================================================
   FILE				: 180Worm.Cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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
					version: 2.5.0.19
					Resource : Shweta
					Description: Fix for Trojan.Agent

					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
					
					version: 2.5.0.32
					Resource : Shweta
					Description: Changed ScanSplSpy for function call CheckReportKeyValueData
========================================================================================*/

#include "pch.h"
#include "180worm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and remove 180 Search Assistant
	Author			: 
	Description		: remove 180 entries from Run and search system32 and windows folders
--------------------------------------------------------------------------------------*/
bool C180Worm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false ;

		if ( !bToDelete )
		{
			CStringArray csRegLocations ;

			csRegLocations . Add ( RUN_REG_PATH ) ;
			if ( m_bScanOtherLocations )
				csRegLocations.Add( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) ) ;

			for ( int i = 0 ; i < csRegLocations.GetCount() ; i++ )
			{
				if ( m_objReg.KeyExists ( csRegLocations [ i ] , HKEY_LOCAL_MACHINE))
				{
					CStringArray	csArrVal , csArrData ;
					m_objReg.QueryDataValue( csRegLocations [ i ] , csArrVal, csArrData, HKEY_LOCAL_MACHINE);

					CString			csValue , csData ;
					int nValCount = (int)csArrVal.GetCount();
					for ( int iCount = 0; iCount < nValCount; iCount++ )
					{
						if(IsStopScanningSignaled())
							return false ;

						csValue = csArrVal.GetAt(iCount);
						csData  = csArrData.GetAt(iCount);

						CString csExt = csData.Right(3);
						if ( csExt.MakeLower() == _T("exe"))
						{
							if(CheckIf180File( csData ))
							{
								if(FindKillReportProcess(csData, m_ulSpyName, bToDelete))
									m_bSplSpyFound = true;

								if( FindReportRegValue(csRegLocations [ i ], csValue,  m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, true))
									m_bSplSpyFound = true;
							}
						}
					}
				}

				if( FindReportRegValue ( csRegLocations [ i ] , _T("180SA"), m_ulSpyName , HKEY_LOCAL_MACHINE, bToDelete, true))
					m_bSplSpyFound = true;
			}

			m_csArrInfectedFiles.RemoveAll () ;
			m_depth180 = 0 ;
			Determine180File( m_objSysInfo.m_strWinDir, _T("") , _T("180solutions") , 1 ) ; //search recursive 1 sub dirs
			if(m_csExeName.GetLength() != 0)
				Determine180File ( m_objSysInfo . m_strWinDir , _T(".dat") , _T("") , 0 ) ; // search only current dir
		}
		
		//version:19.0.0.039
		//Checked For random Key
		CheckReportKeyValueData ( m_ulSpyName , SOFTWARE , HKEY_LOCAL_MACHINE);
		if ( m_bScanOtherLocations )
			CheckReportKeyValueData ( m_ulSpyName , WOW6432NODE_REG_PATH , HKEY_LOCAL_MACHINE);

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}

	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in C180Worm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIf180File
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: determine if 180 file
	Author			: 
	Description		: matches signatures to check if 180 file
--------------------------------------------------------------------------------------*/
bool C180Worm :: CheckIf180File ( CString csFileName)
{
	try
	{
		BYTE bMD5Signature[16] = {0};
		if(m_pFileSigMan->GetMD5Signature(csFileName, bMD5Signature))
		{
			const BYTE MD5_180SEARCH_1[16] = {0xBF,0x84,0x89,0xEF,0x5E,0x9B,0xDF,0xC2,0x1F,0xFD,0x2B,0x7D,0xE5,0xBB,0x54,0x6C};
			const BYTE MD5_180SEARCH_2[16] = {0x37,0xC9,0xF9,0x31,0x7F,0xB2,0x89,0x0A,0x54,0x8B,0xDA,0x5C,0xA3,0x59,0xE5,0x9E};
			const BYTE MD5_180SEARCH_3[16] = {0xD8,0x0B,0xB0,0x86,0x96,0xA2,0x89,0xDA,0x5B,0x1A,0xEE,0xF0,0x5E,0xB0,0xF8,0xA4};
			const BYTE MD5_180SEARCH_4[16] = {0x6C,0x60,0xF3,0xB2,0xC8,0xAF,0x3F,0x67,0x83,0x6D,0xAD,0x09,0x8E,0x90,0xA0,0x44};

			//180sa Random exe signature
			if(!memcmp(bMD5Signature, MD5_180SEARCH_1, 16) || !memcmp(bMD5Signature, MD5_180SEARCH_2, 16)
				|| !memcmp(bMD5Signature, MD5_180SEARCH_3, 16) || !memcmp(bMD5Signature, MD5_180SEARCH_4, 16))
				return true;
			else
				return false;
		}
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in C180Worm::CheckIf180File(), Error : %d"),GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: Determine180File
	In Parameters	: CString , CString , CString , int
	Out Parameters	: 
	Purpose			: search for 180 files
	Author			: Shweta M
	Description		: searches for 180 files
					  iSubFolderDepth ==  0 then scan only csSearchFolder dir
					  if iSubFolderDepth ==  1 then scan csSearchFolder and 1 sub dir under csSearchFolder
--------------------------------------------------------------------------------------*/
bool C180Worm :: Determine180File ( CString csSearchFolder, CString csExt, CString csCompanyName, int iSubFolderDepth )
{
	try
	{
		BOOL	bFound = TRUE;
		bool	bSearchDatFiles = false ;
		CString csFullFileName , csPath ;
		CFileFind		objFile;

		if( -1 == iSubFolderDepth )
		{
			return true;
		}
		iSubFolderDepth--;
		if ( csExt == _T(".dat") )
		{
			// If by chance m_csExeName has come blank, when searching for dat files, return false. 
			// Searching further may end up searching all windows folder for *.dat files.
			if ( m_csExeName == _T("") )
				return false;
			
			bSearchDatFiles = true ;
			csPath = csSearchFolder + _T("\\") + m_csExeName + _T("*.dat") ;
		}
		else
			csPath = csSearchFolder + _T("\\*") ;
		
		bFound = objFile.FindFile( csPath );
		if ( !bFound )
			return false;
		
		while ( bFound )
		{
			bFound = objFile.FindNextFile();
			if ( objFile.IsDots() )
				continue ;
			
			csFullFileName  =  csSearchFolder + _T("\\") + objFile.GetFileName();
			if ( !objFile.IsDirectory() &&  m_depth180 != iSubFolderDepth)
			{
				CString	 csExtension  =  csFullFileName.Right( 3 );
				csExtension.MakeLower();
				if ( csExtension == _T("exe") || csExtension == _T("dll") )
				{
					if ( CheckCompanyName ( csFullFileName , csCompanyName))
					{
						if ( csExtension == _T("exe") )
							m_csExeName = csFullFileName ;
						
						if( FindKillReportProcess(csFullFileName, m_ulSpyName, false))
						{
							m_bSplSpyFound = true;
							m_csArrInfectedFiles.Add(csFullFileName );
						}
					}
				}
				else if ( bSearchDatFiles && ( csExtension == _T("dat") ) )
				{
                    
					SendScanStatusToUI ( Special_File , m_ulSpyName , csFullFileName  ) ;
					m_csArrInfectedFiles.Add ( csFullFileName );
				}
			}

			if(objFile.IsDirectory())
			{
				if ( StrCmpI ( m_objSysInfo.m_strSysDir , csFullFileName ) )
				{
					Determine180File ( csFullFileName, csExt , csCompanyName , iSubFolderDepth ) ;
				}
			}
		}
		objFile.Close() ;
		return  false ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in C180Worm::Determine180File(), Error : %d"),GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}
