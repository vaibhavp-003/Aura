/*=====================================================================================
   FILE				: SplSpyWrapper.cpp
   ABSTRACT			: This class contains functions for scanning and quarantining all spyware
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
   VERSION HISTORY	:
======================================================================================*/
#include "pch.h"
#include "EnumProcess.h"
#include "SDSystemInfo.h"
#include "SplSpyWrapper.h"
#include "DirectoryManager.h"
#include "ChromePreference.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

DWORD g_dwCount = 0;

//leave this function and its calls commented as they are required to check time taken in scanning
void _Print_The_Class_Name(LPCTSTR szString)
{
	TCHAR szCount[20] = {0};
	_stprintf_s(szCount, _countof(szCount), _T("%u"), g_dwCount);
	AddLogEntry(L"%s", szCount);
	g_dwCount++;
}

/*-------------------------------------------------------------------------------------
	Function		: CSplSpyWrapper
	In Parameters	: SENDSCANMESSAGE, LPVOID 
	Out Parameters	: 
	Purpose			: construct the object
	Author			: Anand
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CSplSpyWrapper::CSplSpyWrapper( SENDMESSAGETOUI lpSndMessage , const CString& csDrivesToScan )
{
	  pAuroraScan = NULL;
	  p180Scan = NULL;
	  p2ndThoughtScan = NULL;
	  pAddGunScan = NULL;
	  pE2GiveScan = NULL;
	  pErrorSafeScan = NULL;
	  pHotbarScan = NULL;
	  pHSAScan = NULL;
	  pIEPluginScan = NULL;
	  pLookToMeScan = NULL;
	  pLOPScan = NULL;
	  pMSDirectScan = NULL;
	  pNewDotNetScan = NULL;
	  pPurityScan = NULL;
	  pRandomScan = NULL;
	  pRemotelyAnyScan = NULL;
	  pSurfSideScan = NULL;
	  pWebHancerScan = NULL;
	  pWebSerToolScan = NULL;
	  pWinZipScan = NULL;
	  pXPCSpyScan = NULL;
	  pRunEntryScan = NULL;
	  pCommonNameScan = NULL;
	  pAntiSoldierScan = NULL;
	  pAntiVirusScan = NULL;
	  pAddSaverScan = NULL;
	  pAdwarePopScan = NULL;
	  pBorlandScan = NULL;
	  pCinmusScan = NULL;	   
	  pCoolWebScan = NULL;
	  //pSDBotScan = NULL; 2.5.0.60
	  pEliteKeyLogScan = NULL;
	  pIEBarScan = NULL;
	  pProAgentScan = NULL;
	  pProRatKScan = NULL;
	  pPSGuardScan = NULL;
	  pQuakeScan = NULL;
	  pRedHandedScan = NULL;
	  pSmokingGunScan = NULL;
	  pSpyAxeScan = NULL;
	  pSpyStrikeScan = NULL;
	  pSpyBotScan = NULL;
	  pSpyFalconScan = NULL;
	  pStarWareScan = NULL;
	  pVirusBurstScan = NULL;
	  pInternerOptScan = NULL;
	  pKeyKeyScan = NULL;
	  pVirusBlastScan = NULL;
	  pWinAntiSpyScan = NULL;
	  pWinVirusScan = NULL;
	  pWinFixerScan = NULL;
	  pWinFoundScan = NULL;
	  pWinKernelScan = NULL;
	  pDialerPhonetScan = NULL;
	  pBeyondKeyloggerScan = NULL;
	  pRandomInfectedFileScan = NULL;
	  pInfectedFileScan		 =	NULL;
	  pTrojanQQPassWorm      = NULL;
	  pSpylockScan			= NULL;
	  pSystemScan			= NULL;
	  pSpyCrushScan			= NULL ;	//Version: 2.5.0.2 Resource : Anand
	  pBustedScan			= NULL ;    // Version 2.5.0.10 Resource: Avinash B
	  pVirusProtectScan		= NULL ;	// 2.5.0.13
	  pAntiVirGearScan		= NULL ;    // 2.5.0.17
	  pTrojanAgentScan		= NULL ;    // 2.5.0.19
	  pGenericToolbaScan	= NULL ;
	  pInvisibleKeylogger   = NULL ;    //2.5.0.28
	  pMalwareBotScan		= NULL ;	//2.5.0.29
	  pCnsminScan			= NULL ;	//2.5.0.30
	  pLastDefenderScan		= NULL ;    //2.5.0.31
	  pAdvancedSpyScan		= NULL ;    //2.5.0.31
	  pTrojanZlobScan		= NULL ;	//2.5.0.31
	  pRandomDrivers		= NULL ;
	  pFraudTool			= NULL ;	//2.5.0.34
	  pMalwareProtector		= NULL ;
	  pAVXPScan				= NULL ;	//2.5.0.36
	  pMultipleSpyScan		= NULL ;
	  pFakeSecurityAlertScan= NULL ;	//2.5.0.49
	  pXPProScan			= NULL ;
	  pPcClientScan			= NULL ;
	  peAntivirusProScan	= NULL ;  //2.5.0.53
	  pAntiMalware2009Scan	= NULL ;
	  pWinWebSecurityWorm	= NULL ; //2.5.0.61
	  pDownloaderZlobWorm	= NULL ; //2.5.0.62
	  pSpywareGuardWorm		= NULL ;
	  pAntivirusWorm		= NULL ;
	  pGenHostScanner		= NULL ; //2.5.0.66
	  pVirusDoctor			= NULL ; //2.5.0.70
      pCOSFiles             = NULL ; //2.5.0.74
	  pNaviPromoWorm		= NULL ; //2.5.0.75
	  pGenAutorunInfWorm	= NULL ; //2.5.0.76
	  pMalwareCatcher		= NULL ; //2.5.0.79
	  pVirusShield			= NULL ;
	  pLSPFixWorm			= NULL ;
	  pPoison				= NULL; //2.5.1.03
	  pGenScanner           = NULL ;//2.5.1.03
	  pGenAppDll            = NULL ;
	  pGenActiveSetup		= NULL ;
	  pPalevoWorm			= NULL ;
	  pFakeLivePCGuard		= NULL;
	  pSdra64				= NULL;
	  pBaidu				= NULL;
	  pAecSys				= NULL;
	  pScapeGoat			= NULL;	  
	  pPackedKrap			= NULL;
	  pFakeMajorDefenceKit	= NULL;
	  pHeurScanWorm			= NULL;
	  pKidoWorm				= NULL;
	  pThinkPointWorm		= NULL;
	  pGlobalRootFix		= NULL;
	  

	  m_pFileSigMan = NULL;
	  m_bSigDbRequiredForQuarantine = false;
	  m_lpSndMessage = lpSndMessage;
	  m_csDrivesToScan = csDrivesToScan ;
	  m_bFSRedirectionDisabled = false ;
	  m_bRestartMachineAfterQuarantine = false ;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CSplSpyWrapper
	In Parameters	: 
	Out Parameters	: 
	Purpose			: destroy the object
	Author			: Anand
	Description		: delete all the variables and destroy the object
--------------------------------------------------------------------------------------*/
CSplSpyWrapper::~CSplSpyWrapper(void)
{
	CleanUp();
	EnableFileSystemRedirection();
}

void CSplSpyWrapper::CleanUp(CSplSpyScan *&pSpyScanner)
{
	if(pSpyScanner)
	{
		delete pSpyScanner;
		pSpyScanner = NULL;
	}
	_ASSERTE(AfxCheckMemory());
}

/*-------------------------------------------------------------------------------------
	Function		: CleanUp
	In Parameters	: 
	Out Parameters	: 
	Purpose			: delete all variables
	Author			: Anand
	Description		: delete all the variables
--------------------------------------------------------------------------------------*/
void CSplSpyWrapper::CleanUp()
{
	// Darshan
	// Version: 2.5.0.36
	CleanUp((CSplSpyScan *&)pAuroraScan);
	CleanUp((CSplSpyScan *&)pAntiSoldierScan);
	CleanUp((CSplSpyScan *&)pAntiVirusScan);
	CleanUp((CSplSpyScan *&)pAddSaverScan);
	CleanUp((CSplSpyScan *&)p180Scan);
	CleanUp((CSplSpyScan *&)p2ndThoughtScan);
	CleanUp((CSplSpyScan *&)pAddGunScan);
	CleanUp((CSplSpyScan *&)pAdwarePopScan);
	CleanUp((CSplSpyScan *&)pBorlandScan);
	CleanUp((CSplSpyScan *&)pCinmusScan);
	CleanUp((CSplSpyScan *&)pCoolWebScan);
	//CleanUp((CSplSpyScan *&)pSDBotScan); 2.5.0.60
	CleanUp((CSplSpyScan *&)pEliteKeyLogScan);
	CleanUp((CSplSpyScan *&)pIEBarScan);
	CleanUp((CSplSpyScan *&)pProAgentScan);
	CleanUp((CSplSpyScan *&)pProRatKScan);
	CleanUp((CSplSpyScan *&)pPSGuardScan);
	CleanUp((CSplSpyScan *&)pQuakeScan);
	CleanUp((CSplSpyScan *&)pRedHandedScan);
	CleanUp((CSplSpyScan *&)pSmokingGunScan);
	CleanUp((CSplSpyScan *&)pSpyAxeScan);
	CleanUp((CSplSpyScan *&)pSpyStrikeScan);
	CleanUp((CSplSpyScan *&)pSpyBotScan);
	CleanUp((CSplSpyScan *&)pStarWareScan);
	CleanUp((CSplSpyScan *&)pVirusBurstScan);
	CleanUp((CSplSpyScan *&)pInternerOptScan);
	CleanUp((CSplSpyScan *&)pKeyKeyScan);
	CleanUp((CSplSpyScan *&)pVirusBlastScan);
	CleanUp((CSplSpyScan *&)pWinAntiSpyScan);
	CleanUp((CSplSpyScan *&)pWinVirusScan);
	CleanUp((CSplSpyScan *&)pWinFixerScan);
	CleanUp((CSplSpyScan *&)pWinFoundScan);
	CleanUp((CSplSpyScan *&)pRandomScan);
	CleanUp((CSplSpyScan *&)pWinKernelScan);
	CleanUp((CSplSpyScan *&)pDialerPhonetScan);
	CleanUp((CSplSpyScan *&)pE2GiveScan);
	CleanUp((CSplSpyScan *&)pErrorSafeScan);
	CleanUp((CSplSpyScan *&)pHotbarScan);
	CleanUp((CSplSpyScan *&)pHSAScan);
	CleanUp((CSplSpyScan *&)pIEPluginScan);
	CleanUp((CSplSpyScan *&)pLookToMeScan);
	CleanUp((CSplSpyScan *&)pLOPScan);
	CleanUp((CSplSpyScan *&)pMSDirectScan);
	CleanUp((CSplSpyScan *&)pNewDotNetScan);
	CleanUp((CSplSpyScan *&)pPurityScan);
	CleanUp((CSplSpyScan *&)pRemotelyAnyScan);
	CleanUp((CSplSpyScan *&)pSurfSideScan);
	CleanUp((CSplSpyScan *&)pWebHancerScan);
	CleanUp((CSplSpyScan *&)pWebSerToolScan);
	CleanUp((CSplSpyScan *&)pWinZipScan);
	CleanUp((CSplSpyScan *&)pXPCSpyScan);
	CleanUp((CSplSpyScan *&)pRunEntryScan);
	CleanUp((CSplSpyScan *&)pCommonNameScan);
	CleanUp((CSplSpyScan *&)pSpyFalconScan);
	CleanUp((CSplSpyScan *&)pBeyondKeyloggerScan);
	CleanUp((CSplSpyScan *&)pInfectedFileScan);
	CleanUp((CSplSpyScan *&)pRandomInfectedFileScan);
	CleanUp((CSplSpyScan *&)pTrojanQQPassWorm);
	CleanUp((CSplSpyScan *&)pSpylockScan);
	CleanUp((CSplSpyScan *&)pSystemScan);
	CleanUp((CSplSpyScan *&)pSpyCrushScan);
	CleanUp((CSplSpyScan *&)pBustedScan);
	CleanUp((CSplSpyScan *&)pVirusProtectScan);
	CleanUp((CSplSpyScan *&)pAntiVirGearScan);
	CleanUp((CSplSpyScan *&)pTrojanAgentScan);
	CleanUp((CSplSpyScan *&)pGenericToolbaScan);
	CleanUp((CSplSpyScan *&)pInvisibleKeylogger);
	CleanUp((CSplSpyScan *&)pMalwareBotScan);
	CleanUp((CSplSpyScan *&)pCnsminScan);
	CleanUp((CSplSpyScan *&)pLastDefenderScan);
	CleanUp((CSplSpyScan *&)pAdvancedSpyScan);
	CleanUp((CSplSpyScan *&)pTrojanZlobScan);
	CleanUp((CSplSpyScan *&)pRandomDrivers);
	CleanUp((CSplSpyScan *&)pFraudTool);
	CleanUp((CSplSpyScan *&)pMalwareProtector);
	CleanUp((CSplSpyScan *&)pAVXPScan);
	CleanUp((CSplSpyScan *&)pMultipleSpyScan);
	CleanUp((CSplSpyScan *&)pFakeSecurityAlertScan);//2.5.0.49
	CleanUp((CSplSpyScan *&)pXPProScan);
	CleanUp((CSplSpyScan *&)pPcClientScan);
	CleanUp((CSplSpyScan *&)peAntivirusProScan);//2.5.0.53
	CleanUp((CSplSpyScan *&)pAntiMalware2009Scan);
	CleanUp((CSplSpyScan *&)pWinWebSecurityWorm );//2.5.0.61
	CleanUp((CSplSpyScan *&)pDownloaderZlobWorm );//2.5.0.62
	CleanUp((CSplSpyScan *&)pSpywareGuardWorm );
	CleanUp((CSplSpyScan *&)pAntivirusWorm );
	CleanUp((CSplSpyScan *&)pGenHostScanner );
	CleanUp((CSplSpyScan *&)pVirusDoctor);//2.5.0.70
    CleanUp((CSplSpyScan *&)pCOSFiles);//2.5.0.74
	CleanUp((CSplSpyScan *&)pNaviPromoWorm);//2.5.0.75
	CleanUp((CSplSpyScan *&)pGenAutorunInfWorm);//2.5.0.76
	CleanUp((CSplSpyScan *&)pMalwareCatcher);//2.5.0.79
	CleanUp((CSplSpyScan *&)pVirusShield);
	CleanUp((CSplSpyScan *&)pLSPFixWorm);
	CleanUp((CSplSpyScan *&)pPoison);//2.5.1.03
	CleanUp((CSplSpyScan *&)pGenScanner);
	CleanUp((CSplSpyScan *&)pGenAppDll);
	CleanUp((CSplSpyScan *&)pGenActiveSetup);
	CleanUp((CSplSpyScan *&)pPalevoWorm);
	CleanUp((CSplSpyScan *&)pFakeLivePCGuard);
	CleanUp((CSplSpyScan *&)pSdra64);
	CleanUp((CSplSpyScan *&)pBaidu);
	CleanUp((CSplSpyScan *&)pAecSys);
	CleanUp((CSplSpyScan *&)pScapeGoat);	
	CleanUp((CSplSpyScan *&)pPackedKrap);
	CleanUp((CSplSpyScan *&)pFakeMajorDefenceKit);
	CleanUp((CSplSpyScan *&)pHeurScanWorm);
	CleanUp((CSplSpyScan *&)pKidoWorm);
	CleanUp((CSplSpyScan *&)pThinkPointWorm);
	CleanUp((CSplSpyScan *&)pGlobalRootFix);
	

	if(m_pFileSigMan)
	{
		UnLoadLocalDatabase();
	}

	m_bSigDbRequiredForQuarantine = false;
	m_bStopScanning = false ;
	m_ulArrSpyName.RemoveAll() ;
	m_iArrDelType.RemoveAll();
	m_csArrEntry.RemoveAll();
}

int CSplSpyWrapper::ScanForDriveIcofolder()
{
	int	iRetValue = 0x00;

	TCHAR		szFolderPath[MAX_PATH] = {0x00};
	TCHAR		szDestFolPath[MAX_PATH] = {0x00};

	_stprintf(szFolderPath,_T("%s\\ "),m_csDrivesToScan);
	_stprintf(szDestFolPath,_T("%s"),m_csDrivesToScan);


	if(PathFileExists(szFolderPath))
	{
		CDirectoryManager		objMaxDir;
		bool bReturn = objMaxDir.MaxMoveDirectory(szDestFolPath, szFolderPath, true,true,true);
		//bool bReturn = objMaxDir.MaxMoveDirectory(szDestFolPath, szFolderPath, true,false);
		if(bReturn)
			objMaxDir.MaxDeleteDirectory(szFolderPath,true);
	}
	
	return iRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: InitSplSpyScan
	In Parameters	: bool bSignature, bool bUSBScan
	Out Parameters	: 
	Purpose			: initiate special spyware scan
	Author			: Anand
	Description		: do a cleanup and call each special spyware scanning function
--------------------------------------------------------------------------------------*/
void CSplSpyWrapper::InitSplSpyScan(bool bSignature, bool bUSBScan)
{
	try
	{
		if(bUSBScan)
		{
			SendScanStatusToUI(Starting_SpecialSpy_Scanner);
			CleanUp();

			pGlobalRootFix = new CGlobalRootFix(this);

			if(IsStopScanningSignaled())	
			{
				return;
			}
			ScanSplSpyware((CSplSpyScan *&)pGlobalRootFix,false);

			//Added by Tushar :  for handling drive icon folder with no name
			ScanForDriveIcofolder();

			return;
		}
		
		FixBrowserLink();	
		SendScanStatusToUI(Starting_SpecialSpy_Scanner);

		CleanUp(); // call cleanup to clean previous allocated pointer, Required for ReScan

		//m_pExcludeDBList.Read();

		pAuroraScan		= new CAuroraWorm(this);
		pTrojanAgentScan		= new CTrojanAgentWorm ( this ) ;//2.5.0.19
		pGenAutorunInfWorm		= new CGenAutorunInfWorm ( this ) ; //2.5.0.76
		pFakeLivePCGuard		= new CFakeLivePCGuard(this);
		pScapeGoat				= new CScapeGoatScan(this);
		pKidoWorm				= new CKidoWorm(this);
		pGlobalRootFix			= new CGlobalRootFix(this);


		if(IsStopScanningSignaled())	
		{
			return;
		}

		//Version: 2.5.0.34
		//Resource: Anand
		//Description: call made to EnablePrivilegesToHandleReg() to enable privileges 
		//				for scanning and quarantining all spyware
		if ( pAuroraScan ) 
		{
			if(pAuroraScan->EnablePrivilegesToHandleReg() == FALSE)
				AddLogEntry(_T("CSplSpyScan::EnablePrivilegesToHandleReg failed!"),0,0);
		}

		//CSystemInfo oSystemInfo;
		if( IsStopScanningSignaled())
		{
			return;
		}

		g_dwCount = 0;
		if(bSignature)
		{
		
		}
		ScanSplSpyware((CSplSpyScan *&)pTrojanAgentScan, true);
		
		ScanSplSpyware((CSplSpyScan *&)pFakeLivePCGuard,true);
		
		ScanSplSpyware((CSplSpyScan *&)pScapeGoat,false);
		
		ScanSplSpyware((CSplSpyScan *&)pKidoWorm,false);
		ScanSplSpyware((CSplSpyScan *&)pGlobalRootFix,false);
		

	}//End Try
	catch(...)
	{
		
		AddLogEntry(_T("Exception caught while scanning for special spyware"), 0, 0);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveSpecialSpywares
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Fix the special spywares
	Author			: 
	Description		: Fixes all the special spywares found, each one by one
					  acquires special token privileges for the process and
					  kills windows explorer before calling fix routine for evert spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper::RemoveSpecialSpywares()
{
	bool bIsExpOpen = false;
	CSystemInfo oSystemInfo;
	
	try
	{
		bool bRet = true;
		AddLogEntry(_T("Starting special spyware removal"), 0, 0);
		if( IsStopScanningSignaled())	
		{
			bRet = false;
            goto RMEND;
		}
		
		//load only if spyware which require signature db
		if(m_bSigDbRequiredForQuarantine)
		{
			//initialize file signature
			if(!m_pFileSigMan)
			{
				LoadLocalDatabase(CSystemInfo::m_strRoot);
			}
		}
		if( IsStopScanningSignaled())	
		{
			bRet = false;
            goto RMEND;
		}
		if(m_bRestartMachineAfterQuarantine )
		{
			KillWindowsExplorer();
		}

		RemoveSplSpyware((CSplSpyScan *&)pSystemScan);
		RemoveSplSpyware((CSplSpyScan *&)pAuroraScan);
		RemoveSplSpyware((CSplSpyScan *&)pAntiSoldierScan);
		RemoveSplSpyware((CSplSpyScan *&)pWinVirusScan);
		RemoveSplSpyware((CSplSpyScan *&)pAddGunScan);
		RemoveSplSpyware((CSplSpyScan *&)pBorlandScan);
		RemoveSplSpyware((CSplSpyScan *&)pCoolWebScan);
		RemoveSplSpyware((CSplSpyScan *&)pCinmusScan);
		//RemoveSplSpyware((CSplSpyScan *&)pSDBotScan); 2.5.0.60
		RemoveSplSpyware((CSplSpyScan *&)pEliteKeyLogScan);
		RemoveSplSpyware((CSplSpyScan *&)pIEBarScan);
		RemoveSplSpyware((CSplSpyScan *&)pProAgentScan);
		RemoveSplSpyware((CSplSpyScan *&)pProRatKScan);
		RemoveSplSpyware((CSplSpyScan *&)pPSGuardScan);
		RemoveSplSpyware((CSplSpyScan *&)pQuakeScan);
		RemoveSplSpyware((CSplSpyScan *&)pSpyAxeScan);
		RemoveSplSpyware((CSplSpyScan *&)pSpyStrikeScan);
		RemoveSplSpyware((CSplSpyScan *&)pSpyBotScan);
		RemoveSplSpyware((CSplSpyScan *&)pVirusBurstScan);
		RemoveSplSpyware((CSplSpyScan *&)pInternerOptScan);
		RemoveSplSpyware((CSplSpyScan *&)pKeyKeyScan);
		RemoveSplSpyware((CSplSpyScan *&)pVirusBlastScan);
		RemoveSplSpyware((CSplSpyScan *&)pWinAntiSpyScan);
		RemoveSplSpyware((CSplSpyScan *&)pWinFixerScan);
		RemoveSplSpyware((CSplSpyScan *&)pWinFoundScan);
		RemoveSplSpyware((CSplSpyScan *&)pRandomScan);
		RemoveSplSpyware((CSplSpyScan *&)pInfectedFileScan);
		RemoveSplSpyware((CSplSpyScan *&)pDialerPhonetScan);
		RemoveSplSpyware((CSplSpyScan *&)pE2GiveScan);
		RemoveSplSpyware((CSplSpyScan *&)pErrorSafeScan);
		RemoveSplSpyware((CSplSpyScan *&)pIEPluginScan);
		RemoveSplSpyware((CSplSpyScan *&)pLookToMeScan);
		RemoveSplSpyware((CSplSpyScan *&)pMSDirectScan);
		RemoveSplSpyware((CSplSpyScan *&)pNewDotNetScan);
		RemoveSplSpyware((CSplSpyScan *&)pSurfSideScan);
		RemoveSplSpyware((CSplSpyScan *&)pWebHancerScan);
		RemoveSplSpyware((CSplSpyScan *&)pWinZipScan);
		RemoveSplSpyware((CSplSpyScan *&)pXPCSpyScan);
		RemoveSplSpyware((CSplSpyScan *&)pRunEntryScan);
		RemoveSplSpyware((CSplSpyScan *&)pCommonNameScan);
		RemoveSplSpyware((CSplSpyScan *&)pSpyFalconScan);
		RemoveSplSpyware((CSplSpyScan *&)pAntiVirusScan);
		RemoveSplSpyware((CSplSpyScan *&)pBeyondKeyloggerScan);
		RemoveSplSpyware((CSplSpyScan *&)pRandomInfectedFileScan);
		RemoveSplSpyware((CSplSpyScan *&)pTrojanQQPassWorm);
		RemoveSplSpyware((CSplSpyScan *&)pRemotelyAnyScan);
		RemoveSplSpyware((CSplSpyScan *&)pSpyCrushScan);
		RemoveSplSpyware((CSplSpyScan *&)pInvisibleKeylogger);
		RemoveSplSpyware((CSplSpyScan *&)pCnsminScan);
		RemoveSplSpyware((CSplSpyScan *&)pTrojanAgentScan);
		RemoveSplSpyware((CSplSpyScan *&)pFraudTool);
		RemoveSplSpyware((CSplSpyScan *&)pRandomDrivers);
		RemoveSplSpyware((CSplSpyScan *&)pMalwareProtector);
		RemoveSplSpyware((CSplSpyScan *&)pDownloaderZlobWorm); // 2.5.0.62
		RemoveSplSpyware((CSplSpyScan *&)pAntivirusWorm);
		RemoveSplSpyware((CSplSpyScan *&)pGenHostScanner);
        RemoveSplSpyware((CSplSpyScan *&)pCOSFiles);//2.5.0.74
		RemoveSplSpyware((CSplSpyScan *&)pLSPFixWorm);
		RemoveSplSpyware((CSplSpyScan *&)pGenActiveSetup);
		RemoveSplSpyware((CSplSpyScan *&)pPalevoWorm);
		RemoveSplSpyware((CSplSpyScan *&)pFakeLivePCGuard);
		RemoveSplSpyware((CSplSpyScan *&)pSdra64);
		RemoveSplSpyware((CSplSpyScan *&)pBaidu);
		RemoveSplSpyware((CSplSpyScan *&)pAecSys);
		RemoveSplSpyware((CSplSpyScan *&)pScapeGoat);
		RemoveSplSpyware((CSplSpyScan *&)pPackedKrap);
		RemoveSplSpyware((CSplSpyScan *&)pFakeMajorDefenceKit);
		RemoveSplSpyware((CSplSpyScan *&)pHeurScanWorm);
		RemoveSplSpyware((CSplSpyScan *&)pKidoWorm);
		RemoveSplSpyware((CSplSpyScan *&)pGlobalRootFix);
		
		RemoveSplSpyware((CSplSpyScan *&)pThinkPointWorm);

		RMEND:
		if(m_pFileSigMan)
		{
			UnLoadLocalDatabase();
		}

		AddLogEntry(_T("Finished special spyware removal"), 0, 0);
		return bRet;

	}//End Try
	
	catch(...)
	{
		if(m_pFileSigMan)
		{
			UnLoadLocalDatabase();
		}

		AddLogEntry(_T("Exception caught in CSplSpyWrapper::RemoveSpecialSpywares") , 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpyware
	In Parameters	: CSplSpyScan *&pSpyScanner, bool bSetRestartFlag, bool bSetSignatureDBFlag
	Out Parameters	: true if spyware found, else false
	Purpose			: calls the derived class scan function
	Author			: Darshan Singh Virdi
	Description		: For all the derived classes to call scan spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper::ScanSplSpyware(CSplSpyScan *&pSpyScanner, bool bSetRestartFlag, bool bSetSignatureDBFlag, bool bCheckExcludeDB)
{
	if(m_bStopScanning) return false;

	if(pSpyScanner)
	{
		if (pSpyScanner->m_bStatusbar)
		{
		if ( m_lpSndMessage )
			m_lpSndMessage (SplSpy_Report, eStatus_Detected, pSpyScanner -> m_ulSpyName , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ) ;
		}

		bool bScan = true;
		//ToDo : EHERE
		//if(bCheckExcludeDB)
		//	bScan = (!pSpyScanner->CheckInExcludeDB(m_pExcludeDBList, pSpyScanner->GetSpywareName()));

		if(bScan)
		{
			if(pSpyScanner->ScanSplSpy(false, m_pFileSigMan))
			{
				//if(bSetRestartFlag) m_bRestartMachineAfterQuarantine = true;
				if(bSetSignatureDBFlag) m_bSigDbRequiredForQuarantine = true;
				return true;
			}
			else
			{
				delete pSpyScanner;
				pSpyScanner = NULL;
			}
		}
	}
	_ASSERTE(AfxCheckMemory());
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveSplSpyware
	In Parameters	: CSplSpyScan *&pSpyScanner
	Out Parameters	: true if removed successfully, else false
	Purpose			: calls the derived class remove spyware function
	Author			: Darshan Singh Virdi
	Description		: For all the derived classes to call remove spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper::RemoveSplSpyware(CSplSpyScan *&pSpyScanner)
{
	if(m_bStopScanning) return false;

	if(pSpyScanner)
	{
		if(pSpyScanner->m_bSplSpyFound)
		{
			return pSpyScanner->ScanSplSpy(true, m_pFileSigMan);
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: KillWindowsExplorer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: kill windows explorer
	Author			: Anand
	Description		: kill windows explorer which is needed to fix some spyware
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper::KillWindowsExplorer()
{
	try
	{
		CEnumProcess objEnumProcess;
		CSystemInfo  objSysInfo;
		if(m_bRestartMachineAfterQuarantine)
		{
			CString csWinPath;
			objEnumProcess.IsProcessRunning ( CSystemInfo::m_strWinDir + _T("\\Explorer.exe") , true, true);

			csWinPath.Format(_T("%s\\Internet Explorer\\IEXPLORE.EXE"), static_cast<LPCTSTR>(objSysInfo.m_strProgramFilesDir));
			objEnumProcess.IsProcessRunning(csWinPath, true, true);
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSplSpyWrapper::KillWindowsExplorer()") , 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SignalStopScanning
	In Parameters	: 
	Out Parameters	: 
	Purpose			: set scanning is to be stopped
	Author			: Anand
	Description		: set the flag of scanning to stop
--------------------------------------------------------------------------------------*/
void CSplSpyWrapper :: SignalStopScanning()
{
	m_bStopScanning = true ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsStopScanningSignaled
	In Parameters	: 
	Out Parameters	: 
	Purpose			: check if scanning is to be stopped
	Author			: Anand
	Description		: return the flag of scanning
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper :: IsStopScanningSignaled()
{
	return m_bStopScanning ;
}

/*-------------------------------------------------------------------------------------
	Function		: SendMessageToUI
	In Parameters	: const CString, const CString, ENUM_WORMTYPE
	Out Parameters	: 
	Purpose			: report the worm to UI
	Author			: Anand
	Description		: call the send message to UI function
--------------------------------------------------------------------------------------*/
//void CSplSpyWrapper :: SendMessageToUI (ULONG ulSpywareName , const CString csValue , SD_Message_Info WormType ,int  iQuarantine )

void CSplSpyWrapper ::SendScanStatusToUI(SD_Message_Info eTypeOfScanner)
{
      if(m_lpSndMessage)
            m_lpSndMessage(eTypeOfScanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

void CSplSpyWrapper::SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR *strValue)
{
      AddLogEntry(eTypeOfScanner, strValue, _T(""));
      if(m_lpSndMessage)
      {
          m_lpSndMessage(eTypeOfScanner, eStatus_Detected, ulSpyName, 0, strValue, 0, 0, 0, 0, 0, 0, 0);
      }
}

void CSplSpyWrapper::SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData)
{
      AddLogEntry(eTypeOfScanner, strKey, strValue, Type_Of_Data, (LPCTSTR)lpbData, _T(""));
      if(m_lpSndMessage)
      {
          m_lpSndMessage(eTypeOfScanner, eStatus_Detected, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data, lpbData,iSizeOfData, 0, 0, 0);
      }
}

void CSplSpyWrapper::SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData)
{
      AddLogEntry(eTypeOfScanner, strKey, strValue, Type_Of_Data, (LPCTSTR)lpbData, _T(""));
      if(m_lpSndMessage)
      {
		m_lpSndMessage(eTypeOfScanner, eStatus_Detected, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data, lpbData, iSizeOfData, psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData);
      }
}

/*-------------------------------------------------------------------------------------
	Function		: LoadLocalDatabase
	In Parameters	: const CString
	Out Parameters	: 
	Purpose			: load local database
	Author			: Anand
	Description		: load the local database for the supplied drive letter
--------------------------------------------------------------------------------------*/
void CSplSpyWrapper :: LoadLocalDatabase(const CString csDriveLetter)
{
	m_csLocalDBFileName = csDriveLetter + SD_DB_LOCAL_SIGNATURE;
	m_pFileSigMan = new CFileSignatureDb;
	//m_pFileSigMan->Read(m_csLocalDBFileName); // not required
}

/*-------------------------------------------------------------------------------------
	Function		: UnLoadLocalDatabase
	In Parameters	: 
	Out Parameters	: 
	Purpose			: unload local database
	Author			: Anand
	Description		: check the pointer and unload the database
--------------------------------------------------------------------------------------*/
void CSplSpyWrapper :: UnLoadLocalDatabase()
{
	if(m_pFileSigMan)
	{
		//m_pFileSigMan->Save(m_csLocalDBFileName);	// not required
		delete m_pFileSigMan;
		m_pFileSigMan = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DisableFileSystemRedirection
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: disable redirection for file system
	Author			: Anand
	Description		: disable redirection for file and folder system and pfdir paths
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper :: DisableFileSystemRedirection()
{
	if ( !m_bFSRedirectionDisabled )
	{
		m_bFSRedirectionDisabled = true ;
	}

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnableFileSystemRedirection
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: disable redirection for file system
	Author			: Anand
	Description		: disable redirection for file and folder system and pfdir paths
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper :: EnableFileSystemRedirection()
{
	if ( m_bFSRedirectionDisabled )
	{
		m_bFSRedirectionDisabled = false ;
	}

	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: AddToCompulsoryDeleteOnRestartList
	In Parameters	: int ,ULONG , const CString&
	Out Parameters	: bool
	Purpose			: Added cumpulsary delete option
	Author			: Shweta
	Description		: Cumpulsary adds the entry in addinrestart.
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper :: AddToCompulsoryDeleteOnRestartList(int iVal, ULONG m_ulSpyName, const CString& csEntry)
{
	m_ulArrSpyName.Add(m_ulSpyName) ;
	m_iArrDelType.Add(iVal);
	m_csArrEntry.Add (csEntry);
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForCompulsoryDeleteOnRestartList
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: Check for cumpulsary add entry option
	Author			: Shweta
	Description		: retrives the entries which were added in Cumpulsary delete
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper :: CheckForCompulsoryDeleteOnRestartList()
{
	CXPProWorm obj (NULL);
	bool bEntriesFound = false;

	for (INT_PTR i = 0 ,iTotal = m_csArrEntry.GetCount() ; i < iTotal ; i++ )
	{
		RESTART_DELETE_TYPE TYPE ;
		TYPE = (RESTART_DELETE_TYPE)m_iArrDelType.GetAt(i);
		obj.AddInRestartDeleteList ( TYPE, m_ulArrSpyName.GetAt(i), m_csArrEntry.GetAt(i) ) ;
		bEntriesFound = true ;
	}
	return ( bEntriesFound ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: FixBrowserLink
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: Fixes the browser shortcuts listed in LnkScan.ini by Pattern Scanner
	Author			: Tushar
	Description		: 
--------------------------------------------------------------------------------------*/
bool CSplSpyWrapper :: FixBrowserLink()
{
	CString			csINIPAth;
	CSystemInfo		objSysInfo;
	TCHAR			szOutData[MAX_PATH] = {0x00};
	TCHAR			szExistingSig[MAX_PATH] = {0x00};
	TCHAR			szCount[MAX_PATH] = {0x00};
	int				iLinkCount = 0x00;
	CString			cszLogLine;
	
	csINIPAth.Format(_T("%s\\Setting\\LnkScan.ini"),objSysInfo.m_strAppPath);

	cszLogLine.Format(_T("SPCLN : Link Scan File ==> %s "),csINIPAth);
	//AddLogEntry(cszLogLine);
	
	GetPrivateProfileString(_T("LNK2CLEAN"),_T("Count"),_T("0"),&szOutData[0x00],MAX_PATH,csINIPAth);
	iLinkCount =  _tcstol(szOutData, 0, 10);

	cszLogLine.Format(_T("SPCLN : Link Count ==> %s "),szOutData);
	//AddLogEntry(cszLogLine);

	if (iLinkCount == 0x00)
	{
		return false;
	}

	for(int i = 1; i <= iLinkCount; i++)
	{
		memset(szOutData, 0, sizeof(szOutData));
		_stprintf_s(szCount, _countof(szCount), _T("%i"), i);
		GetPrivateProfileString(_T("LNK2CLEAN"), szCount, _T(""), szOutData, _countof(szOutData), csINIPAth);
		if(_tcslen(szOutData) != 0x00)
		{
			cszLogLine.Format(_T("SPCLN : Link To Fix ==> %s "),szOutData);
			//AddLogEntry(cszLogLine);
			if(ModifyBrowserLink(szOutData))
			{
				cszLogLine.Format(_T("SPCLN : Successfully Fixed Link ==> %s "),szOutData);
				AddLogEntry(cszLogLine);
			}
		}
	}

	DeleteFile(csINIPAth);

	return true;
}

bool CSplSpyWrapper :: ModifyBrowserLink(LPCTSTR pLinkPath) 
{ 
    HRESULT				hres; 
    IShellLink*			psl; 
	WCHAR				szGotPath[MAX_PATH] = {0x00}; 
    WIN32_FIND_DATA		wfd; 
	bool				bLnkFixed = false;

	CoInitialize(NULL);

    // Get a pointer to the IShellLink interface.
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl); 
    if (SUCCEEDED(hres)) 
    { 
        IPersistFile* ppf; 
        // Get a pointer to the IPersistFile interface. 
        hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf); 

        if (SUCCEEDED(hres)) 
        { 
            //WCHAR wsz[MAX_PATH]; 
            // Ensure that the string is Unicode. 
            //MultiByteToWideChar(CP_ACP, 0, pathLink, -1, wsz, MAX_PATH); 

            // Load the shortcut. 
            hres = ppf->Load(pLinkPath, STGM_READ); 

            if (SUCCEEDED(hres)) 
            { 
                // Get the path to the link target. 
                hres = psl->GetPath(szGotPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_SHORTPATH); 

                if (SUCCEEDED(hres))
                {
                    //hres = psl->SetPath(newTargetPath);
					hres = psl->SetArguments(_T(""));
                    hres = ppf->Save(pLinkPath, TRUE); //save changes
					if (SUCCEEDED(hres)) 
					{ 
						bLnkFixed = true;
					}
                }
                else
                {
                    // Handle the error
                }

            } 
            // Release the pointer to the IPersistFile interface. 
            ppf->Release(); 
        } 
        // Release the pointer to the IShellLink interface. 
        psl->Release(); 
    } 
	CoUninitialize();
    return bLnkFixed; 
}