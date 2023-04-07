/*=======================================================================================
   FILE				: RedHandedWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware RedHanded
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

					version: 2.5.0.31
					Resource : shweta
					Description: Moved RandomVersion function to SplSpyScan. 
========================================================================================*/

#include "pch.h"
#include "redhandedworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForRedHanded
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and fix RedHanded spyware
	Author			: Anand
	Description		: checks and removes RedHanded random folder in pfdir
--------------------------------------------------------------------------------------*/
bool CRedHandedWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		CFileFind	objFile;
		BOOL	bMoreFiles = FALSE ;
		CString csRandomVersion = _T("") , csSubFolderName = _T("") ;
		CStringArray csArrLoc;

		csArrLoc.Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
		{
			csArrLoc.Add ( CSystemInfo::m_strProgramFilesDirX64 ) ;
		}

		for ( int iLocCnt = 0 ; iLocCnt < csArrLoc.GetCount(); iLocCnt++)
		{
			bMoreFiles = objFile.FindFile ( csArrLoc.GetAt(iLocCnt) + _T("\\*") );
			while ( bMoreFiles )
			{
				bMoreFiles = objFile.FindNextFile();
				if ( objFile.IsDots() || !objFile.IsDirectory() )
					continue ;

				if ( IsRandomSpywareFolder ( objFile.GetFilePath() , _T("redhanded") , m_ulSpyName ) )
				{
					m_bSplSpyFound =  true ;
					RemoveFolders ( objFile.GetFilePath(), m_ulSpyName , false ) ;
							
					//Change Made for Scan Random .INI Files & RegistryKey 
					CString csRandomNumber , csFolderName,csRandomVersionWithDot;
					csRandomNumber = "" ;
					csFolderName = objFile .GetFilePath() ;
					int iDashIndex = 0 ;

					iDashIndex = csFolderName . Find ( L"-" , 0 ) ;
					if ( iDashIndex != -1 )
					{
						csRandomNumber = csFolderName . Right ( csFolderName . GetLength() - ( iDashIndex + 1 ) ) ;
						//Scan random regidtry key & report to UI
						CheckForKeyLoggerKeys ( csRandomNumber , L"PCRedHanded" , m_ulSpyName , L"RedHanded" ) ;						
					}
					//Scan Entry of Random Version
					if ( RandomVersion ( csFolderName , csRandomVersion ,csSubFolderName , csRandomVersionWithDot,  L"RedHanded.Net") )
					{
						CheckRandomEntry ( _T("rdlst") , csRandomNumber , csRandomVersion , m_ulSpyName , csArrServiceKeys , csSubFolderName ) ;
						//Scan random .INI files & report to UI
						CheckForKeyLoggerFiles ( csRandomNumber , m_ulSpyName , csSubFolderName ,csRandomVersion , L"RedHanded.Net" ) ;
					}
				}
			}

			objFile.Close();
		}
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CRedHandedWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}