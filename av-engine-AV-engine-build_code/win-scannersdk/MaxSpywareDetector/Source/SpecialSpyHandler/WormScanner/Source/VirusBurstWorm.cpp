/*====================================================================================
   FILE				: VirusBurstWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware VirusBurst
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
#include "virusburstworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForVirusBurst
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleans VirusBurst
	Author			: Anand
	Description		: Runs uninstaller to remove VirusBurst
	Version			: 18.7.0.001
--------------------------------------------------------------------------------------*/
bool CVirusBurstWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		bool	bVirus_Burst	=	false ;
		bool	bVirusBurst		=	false ;
		bool	bVirus_Bursters =	false ;
		bool	bVB				=	false ;

		bool	bVirus_Burst_Other	  =	false ;
		bool	bVirusBurst_Other	  =	false ;
		bool	bVirus_Bursters_Other =	false ;
		bool	bVB_Other			  =	false ;

		bVirusBurst = CheckAndRunUnInstallerWithParam ( CSystemInfo::m_strProgramFilesDir + BACK_SLASH + _T("VirusBurst") , _T("uninst.exe") ,
														_T("/S") , bToDelete ,m_ulSpyName ) ;
		if ( bVirusBurst && bToDelete )
		{
			KillProcess ( _T("VirusBurst") , _T("VirusBurst.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}

		CString csArgs = _T("/S \"_?=") + CSystemInfo::m_strProgramFilesDir + _T("\\Virus-Burst\"") ;
		bVirus_Burst = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("Virus-Burst") , _T("uninst.exe") ,
														csArgs , bToDelete, m_ulSpyName ) ;
		if ( bVirus_Burst && bToDelete )
		{
			KillProcess ( _T("Virus-Burst") , _T("Virus-Burst.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}

		bVB = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("VB"), _T("uninst.exe"), _T("/S"), 
												bToDelete, m_ulSpyName );
		if ( bVB && bToDelete )
		{
			KillProcess ( _T("VB") , _T("VB.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}

		if ( m_bScanOtherLocations )
		{
			bVirus_Burst_Other = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("VirusBurst") , _T("uninst.exe") ,
															_T("/S") , bToDelete ,m_ulSpyName ) ;
			if ( bVirus_Burst_Other && bToDelete )
			{
				KillProcess ( _T("VirusBurst") , _T("VirusBurst.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}

			csArgs = _T("/S \"_?=") + m_csOtherPFDir + _T("\\Virus-Burst\"") ;
			bVirusBurst_Other = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("Virus-Burst") , _T("uninst.exe") ,
															csArgs , bToDelete, m_ulSpyName ) ;
			if ( bVirusBurst_Other && bToDelete )
			{
				KillProcess ( _T("Virus-Burst") , _T("Virus-Burst.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}

			bVB_Other = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("VB"), _T("uninst.exe"), _T("/S"), 
													bToDelete, m_ulSpyName );
			if ( bVB_Other && bToDelete )
			{
				KillProcess ( _T("VB") , _T("VB.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}
		}

		//Version: 19.0.0.002
		//Resource: Anand
		if ( !bToDelete )
		{
			CArray<CStringA,CStringA> csArrKeywords ;

			csArrKeywords . Add ( "UPX0" ) ;
			csArrKeywords . Add ( "UPX1" ) ;
			csArrKeywords . Add ( "CerberusLibW" ) ;
			csArrKeywords . Add ( "EngineListenerWWd" ) ;
			csArrKeywords . Add ( "IEngineListenerW" ) ;
			csArrKeywords . Add ( "mScannerW" ) ;
			csArrKeywords . Add ( "UIScannerEventsWW" ) ;
			csArrKeywords . Add ( "ScanAreaType" ) ;
			csArrKeywords . Add ( "__MIDL___MIDL_itf_Cerber_0257_0001WW" ) ;
			csArrKeywords . Add ( "saProcessesW" ) ;
			csArrKeywords . Add ( "saRegistryWW" ) ;
			csArrKeywords . Add ( "saGuardedRegistryWWW" ) ;
			csArrKeywords . Add ( "saQuickDiskW" ) ;
			csArrKeywords . Add ( "jsaFullDiskWW" ) ;
			csArrKeywords . Add ( "saHostsW" ) ;
			csArrKeywords . Add ( "saCookiesWWW" ) ;
			csArrKeywords . Add ( "saMaxAreaNumberW" ) ;
			csArrKeywords . Add ( "OnCompleteAreaWW" ) ;
			csArrKeywords . Add ( "OnScanningFolder" ) ;
			csArrKeywords . Add ( "u_bstrFolderW" ) ;
			csArrKeywords . Add ( "7OnScanningWW" ) ;
			csArrKeywords . Add ( "_dwScannedItemsW" ) ;
			csArrKeywords . Add ( "OnScannerExceptionWW" ) ;
			csArrKeywords . Add ( "pExceptionPointersWWX" ) ;
			csArrKeywords . Add ( "BSetGoodValue" ) ;
			csArrKeywords . Add ( "GetGoodValue" ) ;
			csArrKeywords . Add ( "xIQuarantineEventsWWW" ) ;
			csArrKeywords . Add ( "OnQuarantineProgress" ) ;
			csArrKeywords . Add ( "~StopOperationWWW" ) ;
			csArrKeywords . Add ( "RunningW" ) ;
			csArrKeywords . Add ( "_bRunningWWW" ) ;
			csArrKeywords . Add ( "OiRebootRequiredWW" ) ;
			csArrKeywords . Add ( "_bRebootRequired" ) ;
			csArrKeywords . Add ( "1.1.4" ) ;
			csArrKeywords . Add ( "unknown compression method" ) ;
			csArrKeywords . Add ( "incorrect data check" ) ;
			csArrKeywords . Add ( "need dictionary" ) ;
			csArrKeywords . Add ( "2002 Mark Adler " ) ;
			csArrKeywords . Add ( "2002 Jean" ) ;
			csArrKeywords . Add ( "loup Gailly" ) ;
			csArrKeywords . Add ( "SunMonTueWedThuFriSat" ) ;
			csArrKeywords . Add ( "JanFebMarAprMayJunJulAugSepOctNovDec" ) ;
			csArrKeywords . Add ( "Web Browser Window" ) ;
			csArrKeywords . Add ( "A__WebBrowserWindow" ) ;
			csArrKeywords . Add ( "Security_NoProtection.dll" ) ;
			csArrKeywords . Add ( "0123456789ABCDEFGHJKMNPQRTUVWXYZ" ) ;
			csArrKeywords . Add ( "0123456789ABCDEF" ) ;
			csArrKeywords . Add ( "08X.TMP" ) ;
			csArrKeywords . Add ( "24674332177522463174342626191" ) ;
			csArrKeywords . Add ( "1825770632175429681055907631" ) ;
			csArrKeywords . Add ( "Transferred key to new machine " ) ;
			csArrKeywords . Add ( "//digitalriver.com/DigitalRight/validateLicense" ) ;

			CheckSubFoldersForVariant ( 6969 , CSystemInfo::m_strProgramFilesDir , csArrKeywords ) ;
			if ( m_bScanOtherLocations )
				CheckSubFoldersForVariant ( 6969 , m_csOtherPFDir , csArrKeywords ) ;
		}

		CString csArguments = _T("/S \"_?=") + CSystemInfo::m_strProgramFilesDir + _T("\\Virus-Bursters\"") ;
		bVirus_Bursters = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("Virus-Busters") , _T("uninst.exe") , 
															csArguments, bToDelete,	m_ulSpyName );
		if ( bVirus_Bursters && bToDelete )
		{
			KillProcess ( _T("Virus-Bursters") , _T("Virus-Busters.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}

		if ( m_bScanOtherLocations )
		{
			csArguments = _T("/S \"_?=") + CSystemInfo::m_strProgramFilesDir + _T("\\Virus-Bursters\"") ;
			bVirus_Bursters_Other = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("Virus-Busters") , _T("uninst.exe") , 
																	  csArguments, bToDelete,	m_ulSpyName ) ;
			if ( bVirus_Bursters_Other && bToDelete )
			{
				KillProcess ( _T("Virus-Bursters") , _T("Virus-Busters.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}
		}

		m_bSplSpyFound = bToDelete ? false : bVirus_Burst || bVirusBurst || bVB || bVirus_Bursters ||
						 bVirus_Burst_Other || bVirusBurst_Other || bVirus_Bursters_Other || bVB_Other ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CVirusBurstWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}