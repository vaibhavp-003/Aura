/*======================================================================================
   FILE				: WininetKernel32Worm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WininetKernel32
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
#include "WininetKernel32Worm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckWininetAndKernel32
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks wininet.dll and kernel32.dll entries in reg
	Author			: Anand
	Description		: check for two values _T("kernel32.dll") and _T("wininet.dll") and
					  if found, check if they point to a valid file and process
					  now function is called once while scanning and then at quarantine
					  all the files found infected in scanning are in an array and are added to restart delete
--------------------------------------------------------------------------------------*/
bool CWininetKernel32Worm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		if ( !bToDelete )
		{
			CheckWininetAndKernel32UnderHive ( HKEY_LOCAL_MACHINE , BLANKSTRING ) ;
			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;

				CString csUserKey = m_arrAllUsers.GetAt(iCnt);
				CheckWininetAndKernel32UnderHive(HKEY_USERS, csUserKey + BACK_SLASH );
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWininetKernel32Worm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckWininetAndKernel32UnderHive
	In Parameters	: HKEY
	Out Parameters	: 
	Purpose			: clean _T("kernel32.dll") and _T("wininet.dll")
	Author			: Anand
	Description		: check for two values _T("kernel32.dll") and _T("wininet.dll") and
					  if found, check if they point to a valid file and process
					  now function is called once while scanning and then at quarantine
					  all the files found infected in scanning are in an array and are added to restart delete
--------------------------------------------------------------------------------------*/
bool CWininetKernel32Worm :: CheckWininetAndKernel32UnderHive(HKEY hHive, CString csMainKey)
{
	try
	{
		CString csData ;
        DWORD dwDataType = 0;
		m_objReg.Get( csMainKey + POL_EXPL_RUN_PATH , _T("kernel32.dll") , csData ,  hHive,&dwDataType) ;
		if ( !csData.IsEmpty() )
		{
			// check if the file exists and also make corresponding entries in UI
			if ( LookFileInPath ( _T("") , csData ) || LookFileInPath ( m_objSysInfo.m_strSysDir, csData ) ||
				LookFileInPath ( m_objSysInfo.m_strWinDir, csData ) )
			{
				m_bSplSpyFound = true ;
				if( FindReportRegValue(csMainKey + POL_EXPL_RUN_PATH, _T("kernel32.dll"), m_ulSpyName , hHive, false, true))
					m_bSplSpyFound = true;

				if(m_bSplSpyFound)
				{
					if(csMainKey.GetLength() == 0)
                        SendScanStatusToUI ( Special_RegVal , m_ulSpyName , hHive , POL_EXPL_RUN_PATH , _T("kernel32.dll") , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;
					else
                        SendScanStatusToUI ( Special_RegVal, m_ulSpyName ,hHive, csMainKey + CString(POL_EXPL_RUN_PATH) , CString(_T("kernel32.dll")) , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;
				}
			}
			csData.Empty();
		}
		
		// try reading _T("wininet.dll") from 'csValue'
        dwDataType = 0;
		m_objReg.Get(csMainKey + POL_EXPL_RUN_PATH , _T("wininet.dll") , csData , hHive ,  &dwDataType) ;
		if ( !csData.IsEmpty() )
		{
			// check if the file exists and also make corresponding entries in UI
			if ( LookFileInPath ( BLANKSTRING , csData ) || LookFileInPath ( m_objSysInfo.m_strSysDir , csData ) ||
				LookFileInPath ( m_objSysInfo.m_strWinDir , csData ) )
			{
				m_bSplSpyFound = true ;
				if( FindReportRegValue(csMainKey + POL_EXPL_RUN_PATH, _T("wininet.dll"), m_ulSpyName , hHive, false, true))
					m_bSplSpyFound = true;

				if(m_bSplSpyFound)
				{
					if(csMainKey.GetLength() == 0)
						SendScanStatusToUI ( Special_RegVal , m_ulSpyName , hHive ,  POL_EXPL_RUN_PATH , _T("wininet.dll") , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
					else
						SendScanStatusToUI ( Special_RegVal , m_ulSpyName ,HKEY_USERS , csMainKey + CString(POL_EXPL_RUN_PATH) ,  CString(_T("wininet.dll"))   , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
				}
			}
		}

		if ( m_bScanOtherLocations && hHive == HKEY_LOCAL_MACHINE )
		{
             dwDataType = 0;
			m_objReg.Get( csMainKey + WOW6432NODE_REG_PATH + UNDERWOW_POL_EXPL_RUN_PATH , _T("kernel32.dll") , csData ,  hHive, &dwDataType) ;
			if ( !csData.IsEmpty() )
			{
				// check if the file exists and also make corresponding entries in UI
				if ( LookFileInPath ( _T("") , csData ) || LookFileInPath ( m_csOtherSysDir, csData ) ||
					LookFileInPath ( m_objSysInfo.m_strWinDir, csData ) )
				{
					m_bSplSpyFound = true ;
					if( FindReportRegValue(csMainKey + WOW6432NODE_REG_PATH + UNDERWOW_POL_EXPL_RUN_PATH, _T("kernel32.dll"), m_ulSpyName , hHive, false, true))
						m_bSplSpyFound = true;

					if(m_bSplSpyFound)
					{
						if(csMainKey.GetLength() == 0)
							SendScanStatusToUI ( Special_RegVal , m_ulSpyName , hHive , (CString)WOW6432NODE_REG_PATH + (CString)UNDERWOW_POL_EXPL_RUN_PATH ,  _T("kernel32.dll") , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;
						else
							SendScanStatusToUI (Special_RegVal ,  m_ulSpyName ,HKEY_USERS, csMainKey + CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_POL_EXPL_RUN_PATH) 
							, CString(_T("kernel32.dll")) , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;
					}
				}
				csData.Empty();
			}
			
			// try reading _T("wininet.dll") from 'csValue'
            dwDataType = 0;
			m_objReg.Get(csMainKey + WOW6432NODE_REG_PATH + UNDERWOW_POL_EXPL_RUN_PATH , _T("wininet.dll") , csData , hHive,&dwDataType ) ;
			if ( !csData.IsEmpty() )
			{
				// check if the file exists and also make corresponding entries in UI
				if ( LookFileInPath ( BLANKSTRING , csData ) || LookFileInPath ( m_csOtherSysDir , csData ) ||
					LookFileInPath ( m_objSysInfo.m_strWinDir , csData ) )
				{
					m_bSplSpyFound = true ;
					if( FindReportRegValue(csMainKey + WOW6432NODE_REG_PATH + UNDERWOW_POL_EXPL_RUN_PATH , _T("wininet.dll"), m_ulSpyName , hHive, false, true))
						m_bSplSpyFound = true;

					if(m_bSplSpyFound)
					{
						if(csMainKey.GetLength() == 0)
                            SendScanStatusToUI ( Special_RegVal , m_ulSpyName , hHive, (CString)WOW6432NODE_REG_PATH + UNDERWOW_POL_EXPL_RUN_PATH , _T("wininet.dll") , dwDataType , (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;                    
						else
							SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_USERS , csMainKey + CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_POL_EXPL_RUN_PATH) 
							, CString(_T("wininet.dll")) , dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR)) ;                            
					}
				}
			}
		}
		
		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWininetKernel32Worm :: CheckWininetAndKernel32UnderHive, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: LookFileInPath
	In Parameters	: CString , CString 
	Out Parameters	: 
	Purpose			: Checks for file in path
	Author			: Anand
	Description		: this function looks for the 'csFile' in 'csPath'
					  if found makes entry in UI for file and process and returns true
--------------------------------------------------------------------------------------*/
bool CWininetKernel32Worm::LookFileInPath ( CString csPath , CString csFile )
{
	try
	{
		// if 'csPath' is empty it means 'csFile' contains full path
		CString csFullFileName = csPath.IsEmpty() ? csFile : csPath + BACK_SLASH + csFile ;
		
		m_bSplSpyFound = FindKillReportProcess( csFullFileName,  m_ulSpyName , false);
		if(m_bSplSpyFound)
			m_csArrWinKerFiles.Add(csFullFileName);

		return m_bSplSpyFound;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWininetKernel32Worm::LookFileInPath, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
