/*======================================================================================
   FILE				: WinFixerWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinFixer
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
   CREATION DATE	: 25/12/2005
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#include "pch.h"
#include "winfixerworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforWinFixer
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and fix WinFixer spyware
	Author			: 
	Description		: checks and removes winfixer services , software , drivers , 
					  registry keys and BHOs
--------------------------------------------------------------------------------------*/
bool CWinFixerWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		// run the uninstaller of winfixer software, choosing right version
		if( _CheckAndRunWinFixerUninstaller(bToDelete))
		{
			m_bSplSpyFound = true;
		}

		if( FindKillReportService(BLANKSTRING, _T("Distributed Link Tracking Client Helper"), m_ulSpyName, bToDelete))
			m_bSplSpyFound = true;

		if( FindKillReportService(BLANKSTRING, _T("Service"), m_ulSpyName, bToDelete))
			m_bSplSpyFound = true;

		if( FindReportRegKey(CString(REG_NOTIFY_ENTRY) + CString(_T("\\style32")), m_ulSpyName, HKEY_LOCAL_MACHINE, false, false))
		{
			m_bSplSpyFound = true;

			CString csData;
			m_objReg.Get(CString(REG_NOTIFY_ENTRY) + CString(_T("\\style32")), _T("DllName"), csData, HKEY_LOCAL_MACHINE);
			if((csData.Trim()).GetLength() != 0)
			{
				if( _taccess_s( csData, 0) == 0)
				{
					CString csNewName;
					if(bToDelete)
					{
						csNewName = csData.Left(csData.ReverseFind('\\')+ 1) + _T("xyz"); //Rename DLL
						MoveFile( csData, csNewName);
						AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csNewName);
					}
					else
						SendScanStatusToUI(Special_File , m_ulSpyName, csNewName);
				}
			}
		}

		if ( m_bScanOtherLocations )
		{
			if( FindReportRegKey ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_REG_NOTIFY_ENTRY) 
				+ CString(_T("style32")) , m_ulSpyName, HKEY_LOCAL_MACHINE, false, false))
			{
				m_bSplSpyFound = true;

				CString csData;
				m_objReg.Get(CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_REG_NOTIFY_ENTRY) 
					+ CString(_T("style32")), _T("DllName"), csData, HKEY_LOCAL_MACHINE);
				if((csData.Trim()).GetLength() != 0)
				{
					if( _taccess_s( csData, 0) == 0)
					{
						CString csNewName;
						if(bToDelete)
						{
							csNewName = csData.Left(csData.ReverseFind('\\')+ 1) + _T("xyz"); //Rename DLL
							MoveFile( csData, csNewName);
							AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csNewName);
						}
						else
							SendScanStatusToUI(Special_File , m_ulSpyName, csNewName);
					}
				}
			}
		}
		
		if(!bToDelete)
		{
			_ProcessRunEntry(HKEY_LOCAL_MACHINE, _T(""));
			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;
				CString csUserKey = m_arrAllUsers.GetAt(iCnt);
				_ProcessRunEntry(HKEY_USERS, csUserKey + _T("\\"));
			}
		}

		if(RemoveBHOWithKey(_T("{9C5875B8-93F3-429D-FF34-660B206D897A}"), bToDelete, m_ulSpyName))
			m_bSplSpyFound = true;

		if(RemoveBHOWithKey(_T("{C7CF1142-0785-4B12-A280-B64681E4D45E}"), bToDelete, m_ulSpyName))
			m_bSplSpyFound = true;

		if(RemoveBHOWithKey(_T("{1B68470C-2DEF-493B-8A4A-8E2D81BE4EA5}"), bToDelete, m_ulSpyName))
			m_bSplSpyFound = true;

		if(RemoveBHOWithKey(_T("{27EEB0C5-01A9-4A32-8739-C8473346CA87}"), bToDelete, m_ulSpyName))
			m_bSplSpyFound = true;

		if(RemoveBHOWithKey(_T("{702EA91C-1ACF-4772-8078-18F2B2EE1031}"), bToDelete, m_ulSpyName))
			m_bSplSpyFound = true;

		if( FindReportRegKey(_T("Software\\WinFixer 2006"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, false))
			m_bSplSpyFound = true;

		if( FindReportRegKey(_T("Software\\WinFixer_2006"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, false))
			m_bSplSpyFound = true;
		
		//Version:16.7
		//Resource:Anand
		if ( CheckAndRemoveDriver ( m_ulSpyName, _T("WFF"), m_objSysInfo.m_strSysDir + _T("\\Drivers\\Wff.sys"), m_csArrWinFixerWff, bToDelete))
			m_bSplSpyFound = true;

		if ( CheckAndRemoveDriver ( m_ulSpyName, _T("DF_KMD"), m_objSysInfo.m_strSysDir + _T("\\Drivers\\DF_KMD.SYS"), m_csArrWinFixerDf_kmd, bToDelete ))
			m_bSplSpyFound = true;

		//Resource : Anand
		//Version  : 19.0.0.003
		if ( CheckAndRemoveDriver ( m_ulSpyName, _T("FOPN"), m_objSysInfo.m_strSysDir + _T("\\Drivers\\FOPN.sys"), m_csArrWinFixerFOPN, bToDelete))
			m_bSplSpyFound = true;

		//Version:18.7
		//Resource:Anand
		if ( CheckAndRemoveSSODLEntries ( m_ulSpyName, m_csArrWinFixerSSODLRegEntries, m_csArrWinFixerSSODLFileEntries, bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( FindReportRegKey( CString(WOW6432NODE_REG_PATH) + CString(_T("WinFixer 2006")), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, false))
				m_bSplSpyFound = true;

			if( FindReportRegKey( CString(WOW6432NODE_REG_PATH) + CString(_T("WinFixer_2006")), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, false))
				m_bSplSpyFound = true;
			
			//Version:16.7
			//Resource:Anand
			if ( CheckAndRemoveDriver ( m_ulSpyName, _T("WFF"), m_csOtherSysDir + _T("\\Drivers\\Wff.sys"), m_csArrWinFixerWff, bToDelete))
				m_bSplSpyFound = true;

			if ( CheckAndRemoveDriver ( m_ulSpyName, _T("DF_KMD"), m_csOtherSysDir + _T("\\Drivers\\DF_KMD.SYS"), m_csArrWinFixerDf_kmd, bToDelete ))
				m_bSplSpyFound = true;

			//Resource : Anand
			//Version  : 19.0.0.003
			if ( CheckAndRemoveDriver ( m_ulSpyName, _T("FOPN"), m_csOtherSysDir + _T("\\Drivers\\FOPN.sys"), m_csArrWinFixerFOPN, bToDelete))
				m_bSplSpyFound = true;
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinFixerWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckAndRunWinFixerUninstaller
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and Run WinFixer Uninstaller
	Author			: 
	Description		: This function makes entries to UI when the 'bToDelete' flag is true
					  and runs the uninstaler when the flag is false to remove winfixer
--------------------------------------------------------------------------------------*/
bool CWinFixerWorm::_CheckAndRunWinFixerUninstaller(bool bToDelete)
{
	try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;

		bool bFound = false;
		bool bAtLeastOneFound = false ;

		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinFixer 2005") , _T("unins000.exe"), _T("/VERYSILENT /NORESTART") , bToDelete ,
													m_ulSpyName );
		if ( bFound && bToDelete )
			_HandleUninstaller (m_ulSpyName);
		bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinFixer_2006"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") , bToDelete ,
												   m_ulSpyName);
		if ( bFound && bToDelete )
			_HandleUninstaller ( m_ulSpyName);
		bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinFixer 2006") , _T("unins000.exe"), _T("/VERYSILENT /NORESTART") , bToDelete ,
												   m_ulSpyName ) ;
		if ( bFound && bToDelete )
			_HandleUninstaller ( m_ulSpyName ) ;
		bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

		bFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinFixerFree"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART"), bToDelete , m_ulSpyName);
		if ( bFound && bToDelete )
			_HandleUninstaller( m_ulSpyName ) ;
		bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

		if ( m_bScanOtherLocations )
		{
			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinFixer 2005") , _T("unins000.exe"), _T("/VERYSILENT /NORESTART") , bToDelete ,
														m_ulSpyName );
			if ( bFound && bToDelete )
				_HandleUninstaller (m_ulSpyName);
			bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinFixer_2006"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") , bToDelete ,
													   m_ulSpyName);
			if ( bFound && bToDelete )
				_HandleUninstaller ( m_ulSpyName);
			bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinFixer 2006") , _T("unins000.exe"), _T("/VERYSILENT /NORESTART") , bToDelete ,
													   m_ulSpyName ) ;
			if ( bFound && bToDelete )
				_HandleUninstaller ( m_ulSpyName ) ;
			bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;

			bFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinFixerFree"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART"), bToDelete , m_ulSpyName);
			if ( bFound && bToDelete )
				_HandleUninstaller( m_ulSpyName ) ;
			bAtLeastOneFound = bFound ? true : bAtLeastOneFound ;
		}

		return bAtLeastOneFound;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinFixerWorm::_CheckAndRunWinFixerUninstaller, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ProcessRunEntry
	In Parameters	: HKEY
	Out Parameters	: 
	Purpose			: Removes Run Entries
	Author			: 
	Description		: Fixes all the random Run key entries
--------------------------------------------------------------------------------------*/
void CWinFixerWorm::_ProcessRunEntry(HKEY hKeyHive, CString csMainKey)
{
	try
	{
		if(IsStopScanningSignaled())
			return;

		if(m_objReg.KeyExists(csMainKey + RUN_REG_PATH, hKeyHive))
		{
			CStringArray	csArrVal, csArrData;
			CString         csValue,  csData;
			m_objReg.QueryDataValue(csMainKey + RUN_REG_PATH, csArrVal, csArrData, hKeyHive);
			int nRunVals = (int)csArrVal.GetCount();
			for(int iCount=0; iCount < nRunVals; iCount++)
			{
				if(IsStopScanningSignaled())
					break;

				csValue = csArrVal.GetAt(iCount);
				csData  = csArrData.GetAt(iCount);
				csValue.Trim().MakeLower();
				csData.Trim().MakeLower();
							
				if( _taccess_s(csData, 0) == 0)
				{
					CString csSignature;
					BYTE byMD5Sig[16] = {0};
					if(m_pFileSigMan->GetMD5Signature(csData, byMD5Sig))
					{
						PrepareMD5String(csSignature, byMD5Sig);
						if(csSignature == _T("496EC9D90953AEB7F259D292E7D3EEAE") || //vwipxspx.exe
							csSignature == _T("09C6DB8D691CBAEFC1D585550896D13C")) //vqvkeaaa.exe
						{
							FindKillReportProcess(csData, m_ulSpyName, false);
							
							csData.Replace(_T(".exe"),_T(".dll"));
							
							FindReportKillOnRestart(csData, m_ulSpyName, false);
							FindReportRegValue(csMainKey + RUN_REG_PATH, csValue, m_ulSpyName, hKeyHive, false, false);
							continue;
						}
					}
				}
			
				if(	csValue.Find(_T("explorer32")) != -1 || (csValue.Find(_T("system")) != -1 && csData.Find(_T("kernels32.exe")) != -1) ||
					csValue.Find(_T("windowsupdate")) != -1 || csValue.Find(_T("intell32")) != -1 ||
					(csValue.Find(_T("controlpanel")) != -1 && csData.Find(_T("popcorn72.exe")) != -1) || 
					(csValue.Find(_T("windows installer")) != -1 && csData.Find(_T("winstall.exe")) != -1) || 
					(csValue.Find(_T("vqvkea")) != -1 && csData.Find(_T("vqvkea")) != -1) ||
					 csValue.Find(_T("sninstall")) != -1 || csValue.Find(_T("drwebupdate")) != -1 ||
					 csValue.Find(_T("paytime")) != -1 || csData.Find(_T("paytime.exe")) != -1 ||
					 csData.Find(_T("sysvcs.exe")) != -1 || csData.Find(_T("wininstall.exe")) != -1 || 
					(csData.Find(_T("split")) != -1 && csData.Find(_T(".exe")) != -1 ) ||
					(csData.Find(_T("vxgame")) != -1 && csData.Find(_T(".exe")) != -1 ) ||
					(csData.Find(_T("ibm")) != -1 && csData.Find(_T(".exe")) != -1 && csValue.Find(_T("shell")) != -1)
					)
				{
				
					int iFind = csData.Find( _T(".exe") ) ;
					if ( iFind != -1 )
					{
						CString csFileName = csData ;

						// remove beginning and trailing _T(" ( double quotes )
						if ( csFileName.GetLength() > 2 )
						{
							if ( csFileName[0] == '_T("' )
								csFileName = csFileName.Mid( 1 , csFileName.GetLength() - 1 ) ;

							if ( csFileName[ csFileName.GetLength() - 1 ] == '_T("' )
								csFileName = csFileName.Left( csFileName.GetLength() - 1 ) ;
						}
							
						if( FindKillReportProcess(csFileName, m_ulSpyName, false))
							m_bSplSpyFound = true;
					}

					//delete registry key even if the exe was not found!
					FindReportRegValue(csMainKey + RUN_REG_PATH, csValue, m_ulSpyName, hKeyHive, false, false);
				}
			}	
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinFixerWorm::_ProcessRunEntry, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: HandleUninstaller
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: handle the message boxes appearing while running uninstaller
	Author			: 
	Description		: clicks appropriate buttons on message boxes appearing
					  and also removes some winfixer entries from registry
--------------------------------------------------------------------------------------*/
void CWinFixerWorm ::_HandleUninstaller( ULONG ulSpywareName )
{
	try
	{
		HandleUninstaller(ulSpywareName);

		// Winfixer uninstallers, sometimes add an entry in the Run key,
		// which points to the winfixer setup and runs automatically on next startup
		CStringArray	csArrValues , csArrData ;

		m_objReg.QueryDataValue ( RUN_REG_PATH , csArrValues , csArrData , HKEY_LOCAL_MACHINE ) ;
		for ( int i = 0 ; i < csArrValues.GetCount() ; i++ )
		{
			csArrValues[ i ].MakeLower() ;
			csArrData[ i ].MakeLower() ;

			if ( -1 != csArrValues[ i ].Find( _T("winfixer") ) || -1 != csArrData[ i ].Find( _T("winfixer") ) )
			{
				m_objReg.DeleteValue ( RUN_REG_PATH , csArrValues [ i ] , HKEY_LOCAL_MACHINE ) ;
			}
		}
		csArrValues.RemoveAll() ;
		csArrData.RemoveAll() ;

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;
			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			m_objReg.QueryDataValue(csUserKey + _T("\\") + RUN_REG_PATH, csArrValues, csArrData, HKEY_USERS);
			for(int i = 0 ; i < csArrValues.GetCount() ; i++)
			{
				csArrValues[ i ].MakeLower();
				csArrData[ i ].MakeLower();

				if ( csArrValues [ i ] == _T("winfixer") || csArrData [ i ] == _T("winfixer") )
					m_objReg.DeleteValue(csUserKey + _T("\\") + RUN_REG_PATH , csArrValues [ i ] , HKEY_USERS);
			}
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinFixerWorm ::_HandleUninstaller, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}
