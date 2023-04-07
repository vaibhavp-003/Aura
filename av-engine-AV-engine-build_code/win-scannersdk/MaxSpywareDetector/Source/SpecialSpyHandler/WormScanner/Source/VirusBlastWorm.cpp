/*======================================================================================
   FILE				: VirusBlastWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware VirusBlast
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
#include "virusblastworm.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

bool g_iWindow1 = false ;
bool g_iWindow2 = false ;
BOOL CALLBACK EnumWindowsProcForVirusBlast ( HWND hwnd , LPARAM lParam );

/*-------------------------------------------------------------------------------------
	Function		: CheckForVirusBlast
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleans VirusBlast
	Author			: Anand
	Description		: Runs uninstaller to remove VirusBlast
	Version			: 18.3
--------------------------------------------------------------------------------------*/
bool CVirusBlastWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;
		
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("VirusBlast"), _T("uninst.exe"),
														   _T("/S") , bToDelete, m_ulSpyName ) )
		   m_bSplSpyFound = true;

		if ( m_bSplSpyFound && bToDelete )
			_HandleUninstallerForVirusBlast ( m_ulSpyName ) ;
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;

		if ( m_bScanOtherLocations )
		{
			if ( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("VirusBlast"), _T("uninst.exe"),
												   _T("/S") , bToDelete, m_ulSpyName ) )
			   m_bSplSpyFound = true;

			if ( m_bSplSpyFound && bToDelete )
				_HandleUninstallerForVirusBlast ( m_ulSpyName ) ;

			m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		}
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CVirusBlastWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: HandleUninstallerForVirusBlast
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: handle the message boxes appearing while running uninstaller
	Author			: 
	Description		: initiates the message callback handler and loops till time limit
--------------------------------------------------------------------------------------*/
void CVirusBlastWorm::_HandleUninstallerForVirusBlast ( ULONG ulSpywareName )
{
	bool bStop = false ;
	time_t Start = time(0) , TimeOut = 1 * 60 ;	// 1 stands for one minute

	g_iWindow1 = false ;
	g_iWindow2 = false ;

	while ( TimeOut > time(0) - Start )
	{
		if ( !EnumWindows ( EnumWindowsProcForVirusBlast , NULL ) )
			break ;

		DoEvents();
	}
	return ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumWindowsProcForVirusBlast
	In Parameters	: HWND , LPARAM 
	Out Parameters	: 
	Purpose			: Callback function for uninstall handler of VirusBlast
	Author			: 
	Description		: kills windows and clicks message boxes
	Version			: 18.3
--------------------------------------------------------------------------------------*/
BOOL CALLBACK EnumWindowsProcForVirusBlast ( HWND hwnd , LPARAM lParam )
{
	TCHAR Title [ 500 ] = { 0 } ;
	TCHAR * t1 = _T("VirusBlast") ;
	TCHAR * t2 = _T("Uninstall :: Virus Blast") ;

	if ( GetWindowText ( hwnd , Title , _countof ( Title ) ) )
	{
		if ( StrNIStr ( (BYTE*)Title , _tcslen ( Title ) * 2 , (BYTE*)t1 , _tcslen ( t1 ) * 2 ) )
		{
      		HWND hBtn = GetDlgItem ( hwnd , IDCANCEL ) ;
			if ( hBtn )
			{
				SendMessage ( hwnd , WM_COMMAND , MAKEWPARAM ( IDCANCEL , BN_CLICKED ) , ( LPARAM ) hBtn ) ;
				g_iWindow1 = true ;
			}
		}

		if ( StrNIStr ( (BYTE*)Title , _tcslen ( Title ) * 2 , (BYTE*)t2 , _tcslen ( t2 ) * 2 ) )
		{
			PostMessage ( hwnd , WM_SYSCOMMAND , SC_CLOSE , 0 ) ;
			g_iWindow2 = true ;
		}
	}

	if ( g_iWindow1 && g_iWindow2 )
		return ( FALSE ) ;

	return ( TRUE ) ;
}
