/*======================================================================================
   FILE				: VirusDoctor.cpp
   ABSTRACT			: 
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
   CREATION DATE	: 10/02/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.70
					Resource : Shweta
					Description: 
========================================================================================*/

#include "pch.h"
#include "VirusDoctor.h"
#include "ExecuteProcess.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: 
	Author			: Shweta M
	Description		: 
--------------------------------------------------------------------------------------*/
bool CVirusDoctorWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		CStringArray csArrFilenFolder;
		CString csFolder ;
		TCHAR cPath[MAX_PATH] = {0};
		CArray <CStringA,CStringA> csArrInfecStr ;
		bool bInfectionFound = false;;

		csArrInfecStr.Add("Faker");
		csArrInfecStr.Add("Cunter");
		csArrInfecStr.Add("Delf");
		csArrInfecStr.Add("Bankfraud");

		SHGetFolderPath ( NULL , CSIDL_COMMON_APPDATA , NULL , NULL , cPath );
		if ( cPath [0] == 0 ) 
			return false;

		EnumFolder ( cPath , csArrFilenFolder ,m_ulSpyName , 2 );
		for ( int i = 0 ; i < csArrFilenFolder.GetCount() ; i++)
		{
			bInfectionFound = false;
			if (!CheckIfValidExtension ( csArrFilenFolder.GetAt(i) , _T(".exe") ) )
			{
				if ( CheckIfValidExtension ( csArrFilenFolder.GetAt(i) , _T(".bd") ) )
					SearchStringsInFile ( csArrFilenFolder.GetAt(i) , csArrInfecStr ) ;
			}
			else
			{
				if ( CheckVersionInfo ( csArrFilenFolder.GetAt(i) , 2 , _T("Virus Doctor") ) )
					bInfectionFound = true;
				else
				{
					CArray <CStringA,CStringA> csArr1;
					csArr1.Add ( "You may scan your PC to locate malware/spyware threats");
					csArr1.Add ( "SystemSecurity");

					if ( SearchStringsInFile ( csArrFilenFolder.GetAt(i) , csArr1 ))
						bInfectionFound = true;
				}
			}
			if ( bInfectionFound ) 
			{
				csFolder = csArrFilenFolder.GetAt(i) ;
				csFolder = csFolder.Left ( csFolder.ReverseFind ( '\\' ) ) ;
				RemoveFolders ( csFolder , m_ulSpyName , false ) ;
			}
		}
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in  CVirusDoctorWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}
