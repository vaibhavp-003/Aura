/*====================================================================================
   FILE				: SurfSideKickWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware SurfSideKick
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
//#include <shfolder.h>
#include "SurfSideKickWorm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckSurfSideKick
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and fixes SurfSideKick
	Author			: 
	Description		: makes dll entry in AppInit_Dlls which is removed by adding file delete on restart
--------------------------------------------------------------------------------------*/
bool CSurfSideKickWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{		
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return m_bSplSpyFound;
		
		CString csData = _T("");
		CFileFind fFile;
		if( !bToDelete )
		{
			CStringArray csArrLocations ;

			csArrLocations . Add ( WNT_WINDOWS_PATH ) ;
			if ( m_bScanOtherLocations )
				csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_WNT_WINDOWS_PATH) ) ;

			for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
			{
				if ( m_objReg.Get( csArrLocations [ i ] , _T("AppInit_DLLs") , csData , HKEY_LOCAL_MACHINE ))
				{
					(csData.Trim()).MakeLower();
					
					int iPos = csData.Find(_T("repairs"));
					if(iPos != -1 )
					{
						CString sFileName = csData.Mid(iPos); 
						CString csnewData = csData ;

						sFileName = sFileName.Left( sFileName.Find( _T(".dll") ) + 4 );
						csnewData.Replace ( sFileName , _T("") );
						sFileName = m_objSysInfo.m_strSysDir + _T("\\") + sFileName;
						
						CString sEntry = CString(HKLM) + CString(BACK_SLASH) + csArrLocations [ i ] 
						+ CString(_T("\\AppInit_DLLs\\\"")) + csData + CString(_T("\" |")) + csnewData;
						//TODO: RegFix
						//SendMessageToUI ( m_ulSpyName, sEntry , Special_RegDataFix_Scanner );
						SendScanStatusToUI ( Special_File , m_ulSpyName, sFileName  );
						m_bSplSpyFound = true;
					}
				}
			}
			
			if(IsStopScanningSignaled())
				return m_bSplSpyFound;

			CFileVersionInfo objFileVer;
			objFileVer . CheckNotifyEntry ( bToDelete ) ;

			
			if(FindReportRegKey(_T("SOFTWARE\\SurfSideKick3"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete))
				m_bSplSpyFound = true;

			if(FindReportRegKey(_T("SOFTWARE\\Classes\\CLSID\\{02EE5B04-F144-47BB-83FB-A60BD91B74A9}"),
											  m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete))
				m_bSplSpyFound = true;
		
			if(FindReportRegValue(RUN_REG_PATH, _T("SurfSideKick 3"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete ))
				m_bSplSpyFound = true;

			if(FindReportRegValue(_T("Software\\Microsoft\\Internet Explorer\\UrlSearchHooks"), _T("{02ee5b04-f144-47bb-83fb-a60bd91b74a9}"), 
												m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete ))
				m_bSplSpyFound = true;

			if ( m_bScanOtherLocations )
			{
				if(FindReportRegKey( CString(WOW6432NODE_REG_PATH) + CString(_T("SurfSideKick3")), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete))
					m_bSplSpyFound = true;

				if(FindReportRegKey( CString(WOW6432NODE_REG_PATH) 
					+ CString(_T("Classes\\CLSID\\{02EE5B04-F144-47BB-83FB-A60BD91B74A9}")),
												  m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete))
					m_bSplSpyFound = true;
			
				if(FindReportRegValue( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) , _T("SurfSideKick 3"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete ))
					m_bSplSpyFound = true;

				if(FindReportRegValue( CString(WOW6432NODE_REG_PATH) 
					+ CString(_T("Microsoft\\Internet Explorer\\UrlSearchHooks")), _T("{02ee5b04-f144-47bb-83fb-a60bd91b74a9}"), 
													m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete ))
					m_bSplSpyFound = true;
			}
			
			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;
				CString csUserKey = m_arrAllUsers.GetAt(iCnt);

				if(FindReportRegValue(csUserKey + BACK_SLASH + RUN_REG_PATH, _T("SurfSideKick 3"), m_ulSpyName, HKEY_USERS, bToDelete ))
					m_bSplSpyFound = true;

				if(FindReportRegKey(csUserKey + _T("\\") + _T("SOFTWARE\\SurfSideKick3"), m_ulSpyName, HKEY_USERS, bToDelete))
					m_bSplSpyFound = true;

				if(FindReportRegValue(csUserKey + _T("\\") + _T("Software\\Microsoft\\Internet Explorer\\UrlSearchHooks"), 
							_T("{02ee5b04-f144-47bb-83fb-a60bd91b74a9}"), m_ulSpyName, HKEY_USERS, bToDelete))
					m_bSplSpyFound = true;
			}
			
			RemoveFolders ( m_objSysInfo.m_strProgramFilesDir + _T("\\SurfSideKick 3") , m_ulSpyName , bToDelete );
			if ( m_bScanOtherLocations )
				RemoveFolders ( m_csOtherPFDir + _T("\\SurfSideKick 3") , m_ulSpyName , bToDelete );
		
			TCHAR FolderName [ MAX_PATH ] = { 0 } ;
			SHGetFolderPath ( 0 , CSIDL_INTERNET_CACHE , NULL , 0 , FolderName ) ;
			CString csFileName ( FolderName ) ;
			csFileName += _T("\\ssk.log") ;

			if(!_taccess_s ( csFileName , 0))
				SendScanStatusToUI(Special_File , m_ulSpyName, csFileName);
		}
		
		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}//End Of try block
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSurfSideKickWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
