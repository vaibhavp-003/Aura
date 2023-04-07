/*=====================================================================================
   FILE				: SplSpyWrapper.h
   ABSTRACT			: This contains class decalration
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
				version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability

				version: 2.5.0.49
					Resource : Shweta
					Description: Added Code for Fake Security Alert

======================================================================================*/

#pragma once
#include "SplSpyScan.h"
#include "AuroraWorm.h"
#include "180Worm.h"
#include "2ndThoughtWorm.h"
#include "AddGunWorm.h"
#include "E2GiveWorm.h"
#include "ErrorSafeWorm.h"
#include "HotBarWorm.h"
#include "HSAWorm.h"
#include "IEPluginWorm.h"
#include "LookToMe.h"
#include "LOPWorm.h"
#include "MSDirectDriver.h"
#include "NewDotNetWorm.h"
#include "PurityScan.h"
#include "RandomEntries.h"
#include "RemotelyAny.h"
#include "SurfSideKickWorm.h"
#include "WebHancerWorm.h"
#include "WebSerToolbarWorm.h"
#include "WinZipWorm.h"
#include "XPCSpyWorm.h"
#include "RunEntryWorm.h"
#include "AntiSoldierWorm.h"
#include "AntiVirusGoldenWorm.h"
#include "AddSaverWorm.h"
#include "AdwarePopUps.h"
#include "BorlandWorm.h"
#include "CinmusWorm.h"
#include "CoolWebSearchWorm.h"
#include "EliteKeyLogWorm.h"
#include "IEBarWorm.h"
#include "ProAgentWorm.h"
#include "ProRatKWorm.h"
#include "PSGuardWorm.h"
#include "QuakeWorm.h"
#include "RedHandedWorm.h"
#include "RandomInfectedFiles.h"
#include "SmokingGunWorm.h"
#include "SpyAxeWorm.h"
#include "SpyStrikeWorm.h"
#include "SpyBotWorm.h"
#include "SpyFalconWorm.h"
#include "StarWareWorm.h"
#include "VirusBurstWorm.h"
#include "InternerOptWorm.h"
#include "KeyKeyWorm.h"
#include "VirusBlastWorm.h"
#include "WinAntiSpyWorm.h"
#include "WinAntiVirusWorm.h"
#include "WinFixerWorm.h"
#include "WinFoundWorm.h"
#include "CommonNameWorm.h"
#include "WininetKernel32Worm.h"
#include "DialerPhoneAccess.h"
#include "BeyondKeyloggerWorm.h"
#include "InfectedFiles.h"
#include "TrojanQQPassWorm.h"
#include "SpylockWorm.h"
#include "SystemScan.h"
#include "SpyCrushWorm.h"
#include "BustedWorm.h"
#include "VirusProtectWorm.h"
#include "AntiVirGear.h"
#include "TrojanAgentWorm.h"
#include "FileSignatureDb.h"
#include "Generic Toolbar.h"
#include "Invisible Keylogger.h" 
#include "MalwareBotWorms.h"	
#include "Cnsmin.h"
#include "TheLastDefender.h"//2.5.0.31
#include "AdvancedSpy.h"//2.5.0.31
#include "TrojanZlobWorm.h" //2.5.0.31
#include "RandomDrivers.h"
#include "FraudTool.h"
#include "MalwareProtector.h"
#include "AVXPWorm.h"
#include "FakeSecurityAlert.h" //2.5.0.49
#include "XPProWorm.h"
#include "PcClientWorm.h"
#include "eAntivirusProWorm.h"
#include "AntiMalware2009Worm.h"
#include "WinWebSecurityWorm.h"
#include "DownloaderZlob.h"
#include "SpywareGuard.h"
#include "Antivirus2009.h"
#include "GenHostScanner.h"
#include "VirusDoctor.h"
#include "COSFiles.h"
#include "NaviPromo.h"
#include "GenAutorunInf.h"
#include "Malwarecatcher.h"
#include "VirusShield.h"
#include "LSPFixWorm.h"
#include "Poison.h" // 2.5.1.03
#include "GenericScanner.h"
#include "GenericAppInitDllScanner.h"
#include "GenActiveSetup.h"
#include "PalevoWorm.h"
#include "FakeLivePCGuard.h"
#include "sdra64.h"
#include "BaiduWorm.h"
#include "AecSys.h"
#include "ScapeGoatScan.h"
#include "PackedKrap.h"
#include "FakeMajorDefenceKit.h"
#include "HeurScanWorm.h"
#include "KidoWorm.h"
#include "ThinkPointWorm.h"
#include "GlobalRootFix.h"

#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

class CSplSpyWrapper
{
private:

	CSplSpyScan *pAuroraScan;
	CSplSpyScan *p180Scan;
	CSplSpyScan *p2ndThoughtScan;
	CSplSpyScan *pAddGunScan;
	CSplSpyScan *pE2GiveScan;
	CSplSpyScan *pErrorSafeScan;
	CSplSpyScan *pHotbarScan;
	CSplSpyScan *pHSAScan;
	CSplSpyScan *pIEPluginScan;
	CSplSpyScan *pLookToMeScan;
	CSplSpyScan *pLOPScan;
	CSplSpyScan *pMSDirectScan;
	CSplSpyScan *pNewDotNetScan;
	CSplSpyScan *pPurityScan;
	CSplSpyScan *pRandomScan;
	CSplSpyScan *pRemotelyAnyScan;
	CSplSpyScan *pSurfSideScan;
	CSplSpyScan *pWebHancerScan;
	CSplSpyScan *pWebSerToolScan;
	CSplSpyScan *pWinZipScan;
	CSplSpyScan *pXPCSpyScan;
	CSplSpyScan *pRunEntryScan;
	CSplSpyScan *pCommonNameScan;
	CSplSpyScan *pAntiSoldierScan;
	CSplSpyScan *pAntiVirusScan;
	CSplSpyScan *pAddSaverScan;
	CSplSpyScan *pAdwarePopScan;
	CSplSpyScan *pBorlandScan;
	CSplSpyScan *pCinmusScan;	   
	CSplSpyScan *pCoolWebScan;
	//CSplSpyScan *pSDBotScan;
	CSplSpyScan *pEliteKeyLogScan;
	CSplSpyScan *pIEBarScan;
	CSplSpyScan *pProAgentScan;
	CSplSpyScan *pProRatKScan;
	CSplSpyScan *pPSGuardScan;
	CSplSpyScan *pQuakeScan;
	CSplSpyScan *pRedHandedScan;
	CSplSpyScan *pSmokingGunScan;
	CSplSpyScan *pSpyAxeScan;
	CSplSpyScan *pSpyStrikeScan;
	CSplSpyScan *pSpyBotScan;
	CSplSpyScan *pSpyFalconScan;
	CSplSpyScan *pStarWareScan;
	CSplSpyScan *pVirusBurstScan;
	CSplSpyScan *pInternerOptScan;
	CSplSpyScan *pKeyKeyScan;
	CSplSpyScan *pVirusBlastScan;
	CSplSpyScan *pWinAntiSpyScan;
	CSplSpyScan *pWinVirusScan;
	CSplSpyScan *pWinFixerScan;
	CSplSpyScan *pWinFoundScan;
	CSplSpyScan *pWinKernelScan;
	CSplSpyScan *pDialerPhonetScan;
	CSplSpyScan *pBeyondKeyloggerScan;
	CSplSpyScan *pInfectedFileScan;
	CSplSpyScan *pRandomInfectedFileScan;
	CSplSpyScan *pTrojanQQPassWorm;
	CSplSpyScan *pSpylockScan;
	CSplSpyScan *pSystemScan;
	CSplSpyScan *pSpyCrushScan;
	CSplSpyScan *pBustedScan;
	CSplSpyScan *pVirusProtectScan ;
	CSplSpyScan *pAntiVirGearScan;//2.5.0.17
	CSplSpyScan *pTrojanAgentScan;//2.5.0.19
	CSplSpyScan *pGenericToolbaScan;
	CSplSpyScan *pInvisibleKeylogger;//2.5.0.28	
	CSplSpyScan *pMalwareBotScan ;	//2.5.0.29
	CSplSpyScan *pCnsminScan;		//2.5.0.30
	CSplSpyScan *pLastDefenderScan; //2.5.0.31
	CSplSpyScan *pAdvancedSpyScan; //2.5.0.31
	CSplSpyScan *pTrojanZlobScan; //2.5.0.31
	CSplSpyScan *pRandomDrivers;
	CSplSpyScan *pFraudTool; //2.5.0.34
	CSplSpyScan *pMalwareProtector;
	CSplSpyScan *pAVXPScan;
	CSplSpyScan *pMultipleSpyScan;
	CSplSpyScan *pFakeSecurityAlertScan; //2.5.0.49
	CSplSpyScan	*pXPProScan;
	CSplSpyScan *pPcClientScan;
	CSplSpyScan *peAntivirusProScan;
	CSplSpyScan *pAntiMalware2009Scan;
	CSplSpyScan *pWinWebSecurityWorm;
	CSplSpyScan *pDownloaderZlobWorm; //2.5.0.62
	CSplSpyScan *pSpywareGuardWorm;
	CSplSpyScan *pAntivirusWorm;
	CSplSpyScan *pGenHostScanner;
	CSplSpyScan *pVirusDoctor;
    CSplSpyScan *pCOSFiles;
	CSplSpyScan *pNaviPromoWorm;
	CSplSpyScan *pGenAutorunInfWorm;
	CSplSpyScan *pMalwareCatcher;
	CSplSpyScan *pVirusShield;
	CSplSpyScan *pLSPFixWorm;
	CSplSpyScan *pPoison;
	CSplSpyScan *pGenScanner;
	CSplSpyScan *pGenAppDll;
	CSplSpyScan *pGenActiveSetup;
	CSplSpyScan *pPalevoWorm;
	CSplSpyScan *pFakeLivePCGuard;
	CSplSpyScan *pSdra64;
	CSplSpyScan *pBaidu;
	CSplSpyScan *pAecSys;
	CSplSpyScan *pScapeGoat;
	CSplSpyScan *pPackedKrap;
	CSplSpyScan *pFakeMajorDefenceKit;
	CSplSpyScan *pHeurScanWorm;
	CSplSpyScan *pKidoWorm;
	CSplSpyScan *pThinkPointWorm;
	CSplSpyScan *pGlobalRootFix;

	CArray<DWORD,DWORD> m_ulArrSpyName;
	CArray<int,int> m_iArrDelType;
	CStringArray m_csArrEntry;

	CFileSignatureDb *m_pFileSigMan; //Signature Scan
	
	// Set to true if sig.db require for quarantine process
	bool m_bSigDbRequiredForQuarantine;
	void CleanUp();

	// new structure variables
	LPVOID m_lpThis ;
	SENDMESSAGETOUI m_lpSndMessage ;
	bool m_bStopScanning ;
	CString m_csLocalDBFileName ;
	bool m_bFSRedirectionDisabled ;
	// new structure variables
	
	bool ScanSplSpyware(CSplSpyScan *&pSpyScanner, bool bSetRestartFlag, bool bSetSignatureDBFlag = false, bool bCheckExcludeDB = true);
	bool RemoveSplSpyware(CSplSpyScan *&pSpyScanner);
	void CleanUp(CSplSpyScan *&pSpyScanner);

	bool ModifyBrowserLink(LPCTSTR pLinkPath); 
	bool FixBrowserLink();


public:
	CString m_csDrivesToScan ;
	bool m_bRestartMachineAfterQuarantine;
	CSplSpyWrapper( SENDMESSAGETOUI lpSndMessage , const CString& csDrivesToScan ) ;
	~CSplSpyWrapper(void);

	// new structure variables
	bool IsStopScanningSignaled() ;
	void SignalStopScanning() ;
	//void SendMessageToUI ( ULONG ulSpywareName , const CString csValue , SD_Message_Info WormType ,int iQuarantine) ;
    void SendScanStatusToUI(SD_Message_Info eTypeOfScanner);
    void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR *strValue);
    void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData);
	void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData);

	bool AddToCompulsoryDeleteOnRestartList(int iVal, ULONG m_ulSpyName, const CString& csEntry);
	bool CheckForCompulsoryDeleteOnRestartList();

	void LoadLocalDatabase(const CString csDriveLetter) ;
	void UnLoadLocalDatabase() ;

	bool DisableFileSystemRedirection() ;
	bool EnableFileSystemRedirection() ;
	// new structure variables
	
	void InitSplSpyScan(bool bSignature, bool bUSBScan = false);
	bool RemoveSpecialSpywares();
	bool KillWindowsExplorer();

	int ScanForDriveIcofolder();
};
