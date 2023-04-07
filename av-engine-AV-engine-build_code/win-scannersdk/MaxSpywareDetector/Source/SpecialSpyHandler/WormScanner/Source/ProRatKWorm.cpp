/*====================================================================================
   FILE				: ProRatKWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware ProRat
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
#include "proratkworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForProRAT
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for ProRAT
	Author			: Anand
	Description		: remove the Run and RunServices entries and also some files
--------------------------------------------------------------------------------------*/
bool CProRatKWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		CString csData ;
		CArray<CStringA,CStringA> csArrKeyWordsList1 ;
		CArray<CStringA,CStringA> csArrKeyWordsList2 ;
		CStringArray csArrKeyWordsList3 ;

		csArrKeyWordsList1 . Add ( "hook.dll" ) ;
		csArrKeyWordsList1 . Add ( "simpole.tlb" ) ;
		csArrKeyWordsList1 . Add ( "software\\microsoft\\windows nt\\currentversion\\winlogon" ) ;
		csArrKeyWordsList1 . Add ( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\explorer\\run" ) ;
		csArrKeyWordsList1 . Add ( "Software\\Classes\\CLSID" ) ;
		csArrKeyWordsList1 . Add ( "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objecta" ) ;

		csArrKeyWordsList2 . Add ( "Client hook allocation failure." ) ;
		csArrKeyWordsList2 . Add ( "Exploiting IP" ) ;
		csArrKeyWordsList2 . Add ( "ACKWIN32.EXE" ) ;
		csArrKeyWordsList2 . Add ( "ADVXDWIN.EXE" ) ;
		csArrKeyWordsList2 . Add ( "TROJAN.EXE" ) ;
		csArrKeyWordsList2 . Add ( "ATRO55EN.EXE" ) ;
		csArrKeyWordsList2 . Add ( "N32SCANW.EXE" ) ;
		csArrKeyWordsList2 . Add ( "ZONEALARM.EXE" ) ;
		csArrKeyWordsList2 . Add ( "HIJACKTHIS.EXE" ) ;
		csArrKeyWordsList2 . Add ( "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ) ;
		csArrKeyWordsList2 . Add ( "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ) ;
		csArrKeyWordsList2 . Add ( "BitchX" ) ;

		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strSysDir + _T("\\winkey.dll") ) ;
		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strSysDir + _T("\\fservice.exe") ) ;
		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strSysDir + _T("\\stdole3.tlb") ) ;
		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strWinDir + _T("\\System\\sservice.exe") ) ;
		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strSysDir + _T("\\reginv.dll") ) ;
		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strWinDir + _T("\\ktd32.atm") ) ;
		csArrKeyWordsList3 . Add ( CSystemInfo :: m_strWinDir + _T("\\services.exe") ) ;

		if ( m_bScanOtherLocations )
		{
			csArrKeyWordsList3 . Add ( m_csOtherSysDir + _T("\\winkey.dll") ) ;
			csArrKeyWordsList3 . Add ( m_csOtherSysDir + _T("\\fservice.exe") ) ;
			csArrKeyWordsList3 . Add ( m_csOtherSysDir + _T("\\stdole3.tlb") ) ;
			csArrKeyWordsList3 . Add ( m_csOtherSysDir + _T("\\reginv.dll") ) ;
		}

		if ( !bToDelete )
			csArrInfecFiles.RemoveAll();

		if ( !bToDelete )
		{
			m_bSplSpyFound  =  FindRegDataInStringFile( RUN_REG_PATH, BLANKSTRING , m_ulSpyName , csArrKeyWordsList1, 
														CSystemInfo::m_strWinDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
			
			m_bSplSpyFound  =  FindRegDataInStringFile( RUNSVC_REG_PATH, BLANKSTRING , m_ulSpyName , csArrKeyWordsList1, 
														CSystemInfo::m_strWinDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
			
			m_bSplSpyFound  =  FindRegDataInStringFile( RUN_REG_PATH, _T("Windows System Service") , m_ulSpyName , csArrKeyWordsList2, 
														CSystemInfo::m_strSysDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
			
			m_bSplSpyFound  =  FindRegDataInStringFile( RUNSVC_REG_PATH, _T("Windows System Service") , m_ulSpyName , csArrKeyWordsList2, 
														CSystemInfo::m_strSysDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);

			if ( m_bScanOtherLocations )
			{
				m_bSplSpyFound  =  FindRegDataInStringFile( CString(WOW6432NODE_REG_PATH) + 
					CString(UNDERWOW_RUN_REG_PATH) , BLANKSTRING , m_ulSpyName , csArrKeyWordsList1, 
															CSystemInfo::m_strWinDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
				
				m_bSplSpyFound  =  FindRegDataInStringFile( CString(WOW6432NODE_REG_PATH) + 
					CString(UNDERWOW_RUNSVC_REG_PATH) , BLANKSTRING , m_ulSpyName , csArrKeyWordsList1, 
															CSystemInfo::m_strWinDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
				
				m_bSplSpyFound  =  FindRegDataInStringFile( CString(WOW6432NODE_REG_PATH) + 
					CString(UNDERWOW_RUN_REG_PATH) , _T("Windows System Service") , m_ulSpyName , csArrKeyWordsList2, 
															CSystemInfo::m_strSysDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
				
				m_bSplSpyFound  =  FindRegDataInStringFile( CString(WOW6432NODE_REG_PATH) 
					+ CString(UNDERWOW_RUNSVC_REG_PATH) , _T("Windows System Service") , m_ulSpyName , csArrKeyWordsList2, 
															CSystemInfo::m_strSysDir, HKEY_LOCAL_MACHINE, csArrInfecFiles);
			}
		
			for ( int i = 0 ; i < csArrKeyWordsList3.GetCount(); i++ )
			{
				if ( _taccess_s ( csArrKeyWordsList3[i], 0 ) == 0 )
				{
					m_bSplSpyFound = true ;
					SendScanStatusToUI ( Special_File , m_ulSpyName , csArrKeyWordsList3 [ i ] ) ;
					csArrInfecFiles.Add( csArrKeyWordsList3 [ i ]);
				}
			}
		}

		//Resource: Anand
		//Description: removed quarantine code cos new components will handle removal
		//Version: 2.5.0.23

		/*
		else
		{
			for ( int i = 0 ; i < csArrInfecFiles.GetCount() ; i++ )
			{	
				MoveFileEx ( csArrInfecFiles [ i ] , NULL , MOVEFILE_DELAY_UNTIL_REBOOT ) ;
			}
		}*/

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CProRatKWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: FindRegDataInStringFile
	In Parameters	: CString ,CString ,CString ,CArray<CStringA,CStringA>& ,CString ,HKEY ,CStringArray&
	Out Parameters	: bool
	Purpose			: check for ProRAT
	Author			: Anand
	Description		: remove the Run and RunServices entries and also some files
--------------------------------------------------------------------------------------*/
bool CProRatKWorm::FindRegDataInStringFile( CString csFullKeyPath, CString csValue, ULONG ulSpyName, CArray<CStringA,CStringA>& csStringFile, 
											CString csDataFindPath, HKEY hHive, CStringArray &csInfectedFileList )
{
	try
	{
		CString csData;
        DWORD dwDataType = 0;
		m_objReg.Get( csFullKeyPath, csValue, csData, hHive,&dwDataType);
		if ( !csData.IsEmpty() )
		{
			CString csHive =  m_objReg.RootKey2String(hHive);
			if ( SearchStringsInFile ( csDataFindPath + BACK_SLASH + csData, csStringFile))
			{
				m_bSplSpyFound = true ;

				CString csFullKeyPathLocal( csHive + BACK_SLASH + csFullKeyPath + REG_SEPERATOR + csValue );

                SendScanStatusToUI ( Special_RegVal ,  ulSpyName,hHive ,csFullKeyPath , csValue , dwDataType , (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
				SendScanStatusToUI ( Special_File , ulSpyName, csDataFindPath + BACK_SLASH + csData );

				csInfectedFileList.Add( csDataFindPath + BACK_SLASH + csData);
			}
		}
		else
			m_bSplSpyFound = false;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CProRatKWorm::FindRegDataInStringFile, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
