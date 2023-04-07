/*=============================================================================
   FILE				: GenericToolbar.Cpp
   ABSTRACT			: Implementation of Special Spyware TrojanAgentWorm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 18/02/2008
   NOTES			:
   VERSION HISTORY	: 2.5.0.28
									
=============================================================================*/
#include "pch.h"
#include "Generic Toolbar.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool ,CFileSignatureDb
	Out Parameters	: bool
	Purpose			: Checks and remove CtrojanAgent
    Author			: Shweta
	Description		: Finds and Displays Trojan Agent dll BHO and CLSID 
--------------------------------------------------------------------------------------*/
bool CGenericToolbar::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{ 
	try
	{
		CStringArray csToolbarKeys ,csArrData ;
		CStringArray csArrLoc;

		csArrLoc.Add(TOOLBAR_REGISTRY_PATH);
		if ( m_bScanOtherLocations )
			csArrLoc.Add(TOOLBAR_REGISTRY_PATH_X64);

		for (int iLocCnt = 0 ; iLocCnt < csArrLoc.GetCount() ; iLocCnt++)
		{
			//Enumerate Toolbar and find the files related to it
			if ( !m_objReg.QueryDataValue ( csArrLoc.GetAt(iLocCnt) , csToolbarKeys ,csArrData, HKEY_LOCAL_MACHINE ) )
				continue;

			for ( int i = 0 ; i < csToolbarKeys.GetCount() ; i++ )
			{
				CString csData , csFileName , csFullKey;
				DWORD dwsize ;
				CStringArray csArrCLSID;

				csArrCLSID.Add ( CLSID_KEY );
				if ( m_bScanOtherLocations )
					csArrCLSID . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid\\")) );

				for ( int iCLSIDcnt = 0 ; iCLSIDcnt < csArrCLSID.GetCount() ; iCLSIDcnt++)
				{
					csFullKey = csArrCLSID.GetAt(iCLSIDcnt) + csToolbarKeys.GetAt(i) + _T("\\InprocServer32") ;
					dwsize = MAX_PATH ;
					m_objReg .Get ( csFullKey , _T("") , csData ,HKEY_LOCAL_MACHINE ) ;
					csFileName = csData ;
					
					if ( GenericToolbarScanner ( csFileName ) )
					{
						m_bSplSpyFound = true ;
						SendScanStatusToUI ( Special_File ,  m_ulSpyName , csFileName  ) ;
						EnumKeynSubKey ( CString(HKLM) + CString(_T("\\")) + CString(TOOLBAR_REGISTRY_PATH)
							+ CString(_T("\\")) + csToolbarKeys.GetAt(i) , m_ulSpyName );
						EnumKeynSubKey ( CString(HKLM) + CString(_T("\\")) + csArrCLSID.GetAt ( iCLSIDcnt ) + csToolbarKeys.GetAt(i) , m_ulSpyName ) ;
					}
				}
			}
		}
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CGenericToolbar::ScanSplSpy(), Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false );
}

/*-------------------------------------------------------------------------------------
	Function		: GenericToolbarScanner
	In Parameters	: const CString
	Out Parameters	: bool
	Purpose			: Scans for Spyware Toolbar		
    Author			: Shweta
	Description		: Checks for random Toolbar 
	Version			: 2.5.0.25
--------------------------------------------------------------------------------------*/
bool CGenericToolbar::GenericToolbarScanner ( const CString csFilenm )
{
	try
	{
		CFileVersionInfo oFileVersionInfo;
		TCHAR* szWhiteList[]=
		{
			_T("msdxm.ocx"),
			_T("twctoolbarie7.dll")
		};
		
		if ( _taccess ( csFilenm , 0 ) )
			return false;

		for(INT_PTR i = 0; i < _countof(szWhiteList); i++)
		{
			if(StrStrI(csFilenm, szWhiteList[i]))
			{
				return false;
			}
		}

		if ( StrStrI ( csFilenm , m_objSysInfo . m_strSysDir ) ||
						StrStrI ( csFilenm , m_objSysInfo . m_strWinDir ) ||
						StrStrI ( csFilenm , m_objSysInfo . m_strSysWow64Dir ) )
		{
			if ( oFileVersionInfo.DoTheVersionJob ( csFilenm , false ) )
			{
				return ( true );
			}
			else
			{
				TCHAR csCmpy [ MAX_PATH ] = { 0 } ;
				if ( oFileVersionInfo.GetCompanyName ( csFilenm , csCmpy ) )
				{
					if ( _tcscmp ( csCmpy , BLANKSTRING ) == 0 )
					{
						return ( true );
					}
				}

				return false;
			}
		}
		return false;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CGenericToolbar::GenericToolbarScanner, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false );
}
