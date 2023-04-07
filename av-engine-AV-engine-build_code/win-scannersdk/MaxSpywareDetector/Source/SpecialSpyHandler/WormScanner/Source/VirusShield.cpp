/*======================================================================================
   FILE				: VirusShield.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware VirusShield
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
   CREATION DATE	: 24/06/2009
   NOTE				:
   VERSION HISTORY	: 2.5.0.81
					
========================================================================================*/

#include "pch.h"
#include "VirusShield.h"

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove Antivirus 2009
	Author			: Shweta M
	Description		: This function checks for random files of Antivirus 2009
--------------------------------------------------------------------------------------*/
bool CVirusShield  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		CString csAppDataPath;
		CFileFind objFileFind;
		
		BOOL bFoundFile = FALSE ;
		TCHAR szPath [ MAX_PATH ] = { 0 } ;

		SHGetFolderPath ( 0, CSIDL_COMMON_APPDATA ,0 , 0, szPath );// get all user application data path
		csAppDataPath . Format ( _T("%s") , szPath );

		bFoundFile = objFileFind.FindFile ( csAppDataPath  +  BACK_SLASH + _T( "*.*" ) ) ;
		
		while ( bFoundFile )
		{
			bFoundFile = objFileFind.FindNextFile();

			if ( objFileFind.IsDots() ) 
				continue ;
			
			if ( objFileFind.IsDirectory() ) 
			{
				if ( _taccess ( objFileFind.GetFilePath() + BACK_SLASH + _T("VShield.exe") , 0 ) == 0 )
				{
					RemoveFolders ( objFileFind.GetFilePath() , m_ulSpyName , bToDelete );
				}
				if ( _taccess ( objFileFind.GetFilePath() + BACK_SLASH + _T("FastAV.exe") , 0 ) == 0 )
				{
					RemoveFolders ( objFileFind.GetFilePath() , 11366 , bToDelete ) ;
				}
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CAntivirus2009::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}
