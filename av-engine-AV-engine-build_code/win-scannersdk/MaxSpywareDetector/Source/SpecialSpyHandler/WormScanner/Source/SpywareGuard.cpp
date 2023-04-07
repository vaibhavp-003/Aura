/*======================================================================================
   FILE				: SpywareGuard.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware SpywareGuard
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
   CREATION DATE	: 12/31/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.64
					Resource : Shweta
					Description: created this class to fix Spyware Guard
========================================================================================*/

#include "pch.h"
#include "SpywareGuard.h"
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
	Purpose			: Check and remove Spyware Guard
	Author			: Shweta M
	Description		: This function checks for random files in Apiniti\dll path. It gets 
					  the name random file name from the file c.cgm and reports to be 
					  Spyware Guard.
--------------------------------------------------------------------------------------*/
bool CSpywareGuardWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		CString csPath ,  csFileName , csRandomFile;
		TCHAR szPath [ MAX_PATH ] = { 0 } ;
		FILE * fp ;
		char cFile[25];

		SHGetFolderPath ( 0, CSIDL_COMMON_APPDATA ,0 , 0, szPath);
		csPath = szPath ; 
		csPath = csPath + BACK_SLASH + _T("Microsoft\\Internet Explorer\\DLLs") ;

		if ( _taccess ( csPath , 0 ) != 0 )
			return false;
		
		csFileName = csPath + BACK_SLASH + _T("c.cgm") ;
		if ( _taccess ( csFileName , 0 ) != 0 )
			return false;

		fp = _wfsopen ( csFileName , _T("r") , SH_DENYNO);
		if ( fp == NULL )
			return ( false );

		if ( fgets ( cFile , 25 , fp ) == NULL )
			return false;
		fclose ( fp );

		csRandomFile = csPath + BACK_SLASH ;
		csRandomFile += cFile ;
		if ( _taccess ( csRandomFile , 0 ) != 0 ) 
			return ( false ) ;

		SendScanStatusToUI ( Special_File , m_ulSpyName , csRandomFile );
		SendScanStatusToUI ( Special_File , m_ulSpyName , csFileName );

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CSpywareGuardWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}
