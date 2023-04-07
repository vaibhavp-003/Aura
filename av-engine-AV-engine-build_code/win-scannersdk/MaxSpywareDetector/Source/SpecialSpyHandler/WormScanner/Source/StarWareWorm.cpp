/*====================================================================================
   FILE				: StarWareWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware StarWare
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
#include "starwareworm.h"
//#include <shfolder.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForStarware
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for Starware
	Author			: Anand
	Description		: check for starware folder in PFDIR
--------------------------------------------------------------------------------------*/
bool CStarWareWorm :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false ;

		CFileFind objFile;
		BOOL bMoreFiles = FALSE ;
		CStringArray csArrLocations ;

		csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			bMoreFiles = objFile.FindFile( csArrLocations [ i ] + _T("\\*.*") );
			while ( bMoreFiles )
			{
				if(IsStopScanningSignaled())
					break ;

				bMoreFiles = objFile.FindNextFile();
				if ( objFile.IsDots())
					continue ;

				if ( -1 != objFile.GetFilePath().Find(CSystemInfo::m_strAppPath))
					continue ;

				if ( objFile.IsDirectory() )
				{
					if ( _CheckIfStarwareFolder ( objFile.GetFilePath(), objFile.GetFileName()))
					{
						m_bSplSpyFound = true ;
						RemoveFolders ( objFile.GetFilePath(), m_ulSpyName, false);

						//Version:  19.0.0.14
						//Resource: Anand
						CString csFullStarwarePath ;
						TCHAR szStarwarePath [ MAX_PATH ] = { 0 } ;
						SHGetFolderPath ( NULL , CSIDL_COMMON_APPDATA , NULL , 0 , szStarwarePath ) ;
						if ( _T('\0') != szStarwarePath [ 0 ] )
						{
							csFullStarwarePath = CString ( szStarwarePath ) + BACK_SLASH + objFile.GetFileName() ;
							if ( !_taccess_s ( csFullStarwarePath , 0 ) )
								RemoveFolders ( csFullStarwarePath , m_ulSpyName , false ) ;
						}
					}
				}
			}
			objFile.Close() ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CStarWareWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfStarwareFolder
	In Parameters	: CString , CString 
	Out Parameters	: bool
	Purpose			: check for Starware
	Author			: Anand
	Description		: checks a given folder if it is starware folder
--------------------------------------------------------------------------------------*/
bool CStarWareWorm :: _CheckIfStarwareFolder ( CString csFolderPath , CString csFolderName )
{
	try
	{
		CString csFileName = BLANKSTRING ;

		CFileVersionInfo oFileVersionInfo;
		if ( ! oFileVersionInfo.DoTheVersionJob(csFolderPath + BACK_SLASH + csFolderName + _T("Uninstall.exe"), false ))
			return  false;

		if ( _taccess_s( csFolderPath + BACK_SLASH + csFolderName + _T("Config.xml") , 0 ) )
			return  false;

		return  true;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CStarWareWorm::_CheckIfStarwareFolder, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}