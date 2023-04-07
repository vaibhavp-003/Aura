/*======================================================================================
FILE				: PolymorphicVirus.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: MaxAVPClean.cpp : Defines the exported functions for the DLL application.
					  This Class implements the polymorphism for the detection of different fammily of malwares.
					  This class manges the mechanism for local db (reduces the repeatetive scaning for sma file with same code)
						
VERSION HISTORY		: 02 Oct 2012 : Categorized viruses in 0x0D.
					  30 Sep 2013 : Implemented REV_ID_TYPE structure (variable.h) for local DB
					  16 Oct 2017 : Revised new structure of REV_ID_TYPE
					  24 Jun 2016 : 1.0.2.68 : GRE_REV_ID : 2 : Added New Viruses in Semipoly Trojan By Santosh
					  05 Oct 2016 : 1.0.2.69 : GRE_REV_ID : 3 : Added New Viruses in Semipoly Trojan By Santosh
						 GR4_REV_ID : 2 : Added New Viruses in Semipoly Virus By Santosh
					  01 Dec 2016 : 1.0.2.70 : GRE_REV_ID : 4 : Added New Viruses in Semipoly Trojan By  + Alisha
						 GRB_REV_ID : 2 : Added New Viruses in Sality By Santosh + Alisha
						 GR4_REV_ID : 3 : Added New Viruses in Semipoly Virus By Santosh + Alisha
					  04 Jan 2017 : 1.0.2.72 : GRE_REV_ID : 5 : Added New Viruses in Semipoly Trojan By Santosh
						 GRB_REV_ID : 3 : Added New Viruses in Sality By Santosh + Alisha
						 GR7_REV_ID : 2 : Added New Viruses in Trojan By Alisha
						 GR5_REV_ID : 2 : Added New Viruses in Non Repairable Trojan By Alisha
					  09 Feb 2017 : 1.0.2.73 : GRE_REV_ID : 6 : Added New Viruses in Semipoly Trojan By Santosh +Tushar
						 GR4_REV_ID : 4 : Added New Viruses in Semipoly Virus By Santosh 
					  29 Mar 2017 : 1.0.2.74 : GR9_REV_ID : 2 : Added New Heuristic By Tushar(Add new class CPolyHeuristics)
						 GR7_REV_ID : 3 : Trojan
						 GRE_REV_ID : 7 : Semipoly Trojan
						 GR4_REV_ID : 4 : Semipoly Virus
						 GR5_REV_ID : 3 : Non Repairable Trojan
					  29 Mar 2017 : 1.0.2.76 : GR4_REV_ID : 6 : Changes in Virus.Pioneer.CZ
					  15 May 2017 : 1.0.2.77 : GR4_REV_ID : 7 : Changes for RansomCry by Alisha
					  26 May 2017 : 1.0.2.78 : GR4_REV_ID : 8 : Semipoly Virus
						 GR5_REV_ID : 4 : Non-Repairable Virus
						 GRE_REV_ID : 8 : Semipoly Trojan
					  27 Jul 2017 : 1.0.2.79 : GRE_REV_ID : 9 : Semipoly Trojan
						 GR4_REV_ID : 9 : Semipoly Virus, Trojan_Ransom
						 GR5_REV_ID : 5 : Non-Repairable Virus
						 GR8_REV_ID : 2 : Expiro
						 GR2_REV_ID : 2 : Rainsong
					 23 Jan 2018 : 1.0.2.84 : GR1_REV_ID : 2 : 
						 GR4_REV_ID : A : 
						 GR5_REV_ID : 6 : 
						 GR7_REV_ID : 4 : 
						 GR8_REV_ID : 3 : 
						 GRE_REV_ID : A : 
   				     08 Feb 2018 : 1.0.2.85 : GR1_REV_ID : 3 : 
						 GR4_REV_ID : B : 
						 GRE_REV_ID : B : 
					 28 Feb 2018 : 1.0.2.86 : GRE_REV_ID : C : 
					 04 Apr 2018 : 1.0.2.87 : GRE_REV_ID : D : Semipoly Trojan
						 GR4_REV_ID : C : Semipoly Virus
						 GR1_REV_ID : 4 : Poly Base
					 26 Apr 2018 : 1.0.2.88 : GR9_REV_ID : 3 : Nimnul Virus
						 GRE_REV_ID : E : Semipoly Trojan + Crab Ransomware
					 13 Jun 2018 : 1.0.2.90 : GR1_REV_ID : 5 : 
						 GR4_REV_ID : D : 
						 GR5_REV_ID : 7 : 
						 GRE_REV_ID : F : 	
=====================================================================================*/

#include "MaxAVPMScan.h"
#include "variables.h"
#include "MaxExceptionFilter.h"
#include "PolymorphicVirus.h"
#include "PolyCensor.h"
#include "PolyExpiro.h"
#include "PolyPolip.h"
#include "PolyNimnul.h"
#include "PolyTrojanPatched.h"
#include "PolySilcer.h"
#include "PolyDelikon.h"
#include "PolyLAMT.h"
#include "PolyDetnat.h"
#include "PolyAfgan.h"
#include "PolyDundun.h"
#include "PolyParite.h"
#include "PolySality.h"
#include "PolyVirut.h"
#include "PolyAlman.h"
#include "PolyChiton.h"
#include "PolyElkern.h"
#include "PolyCTX.h"
#include "PolyDevir.h"
#include "PolyMinit.h"
#include "PolySfcer.h"
#include "PolyMabezat.h"
#include "PolyAlma.h"
#include "PolyTDSS.h"
#include "PolyBolzano.h"
#include "PolyHezhi.h"
#include "PolyXpaj.h"
#include "PolyXpajA.h"
#include "PolyPayBack.h"
#include "PolyDoser.h"
#include "PolyThorin.h"
#include "PolyEtap.h"
#include "PolyJunkComp.h"
#include "PolyZMorph.h"
#include "PolyAOC.h"
#include "PolyChamp.h"
#include "NonRepairable.h"
#include "SemiPoly.h"
#include "PolyLevi.h"
#include "PolyFosforo.h"
#include "PolyZperm.h"
#include "PolyTvido.h"
#include "PolyDriller.h"
#include "PolyAndras.h"
#include "PolyBluwin.h"
#include "PolyAris.h"
#include "PolyRainSong.h"
#include "PolyInrar.h"
#include "PolyDion.h"
#include "PolyPolyk.h"
#include "PolyJolla.h"
#include "PolyVampiro.h"
#include "PolyHatred.h"
#include "PolyVulcas.h"
#include "Trojans.h"
#include "Packers.h"
#include "PolyPioneer.h"
#include "PolyZperMorph.h"
#include "SemiPolyTrojans.h"
#include "PolyCrunk.h"
#include "PolyInduc.h"
#include "PolyFlyStdio.h"
#include "PolyXorer.h"
#include "PolyAlcaul.h"
#include "PolyExpiro64.h"
//#include "PolyFearso.h"
#include "PolyTrojans64.h"
#include "PolyRansom.h"
#include "PolyHeuristics.h"

#include <wintrust.h>
#include <Softpub.h>

HANDLE CPolymorphicVirus::m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);

DWORD m_dwTotalScanTime = 0;
DWORD m_dwTotalRepairTime = 0;
DWORD m_dwNoOfFilesScanned = 0;
DWORD m_dwNoOfFilesRepaired = 0;

DWORD WINAPI CheckDigiSignThread(LPVOID pParam)
{ 
	CPolymorphicVirus	*pVirusScanner = (CPolymorphicVirus *)pParam;

	TCHAR szFile2Chk[MAX_PATH] = {0x00};
	
	_tcscpy(szFile2Chk,reinterpret_cast<TCHAR*>(pParam));

	DWORD dwStatus = 0x00;
	dwStatus = pVirusScanner->CheckIsTrustedDigiCert(szFile2Chk);
	
	return dwStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolymorphicVirus
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolymorphicVirus::CPolymorphicVirus(CMaxPEFile *pMaxPEFile):
m_pFileName(pMaxPEFile->m_szFilePath),
m_pMaxPEFile(pMaxPEFile)
{
	m_pPolyBase = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolymorphicVirus
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolymorphicVirus::~CPolymorphicVirus()
{
	if(m_pPolyBase)
	{
		delete m_pPolyBase;
		m_pPolyBase = NULL;
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: CheckWhiteDigiCert
	In Parameters	: 
	Out Parameters	: Status : 0 : Not Found and 1 : Found
	Purpose			: 
	Author			: Tushar Kadam + Ruapli Sonawane + Anand Shrivastava + Virus Analysis Team
	Description		: Defines the exported functions for the DLL application
--------------------------------------------------------------------------------------*/
/*
DWORD CPolymorphicVirus::CheckWhiteDigiCert()
{
	DWORD	dwRetValue = 0x00;

	CSemiPolyTrojans	objSemiPolyVirus(m_pMaxPEFile);

	dwRetValue = objSemiPolyVirus.DetectWhiteCertificate();
	if (dwRetValue == 10001)
	{
		return 1;
	}

	return dwRetValue;
}
*/

DWORD CPolymorphicVirus::CheckWhiteDigiCert()
{

	DWORD	dwRetValue = 0x00;
	DWORD	dwRetValueThread = 0x00;
	TCHAR	szFile2Check[MAX_PATH] = {0x00};

	HANDLE	m_hDigiSignCheck = NULL;

	CSemiPolyTrojans	objSemiPolyVirus(m_pMaxPEFile);

	dwRetValue = objSemiPolyVirus.DetectWhiteCertificate();
	DWORD dwTimeOut = 0x00;

	if (dwRetValue == 10001)
	{ 
		_tcscpy(szFile2Check,m_pMaxPEFile->m_szFilePath);

		if (m_hDigiSignCheck == NULL)
		{
			m_hDigiSignCheck = ::CreateThread(NULL,0,CheckDigiSignThread,szFile2Check,0,NULL);	
			if (m_hDigiSignCheck != NULL)
			{
				
				dwTimeOut = WaitForSingleObject(m_hDigiSignCheck,200);

				GetExitCodeThread(m_hDigiSignCheck,&dwRetValueThread);
				m_hDigiSignCheck = NULL;
				TerminateThread(m_hDigiSignCheck,0);
				CloseHandle(m_hDigiSignCheck);
			}
		}
	}


	if(dwRetValueThread == 259 && dwTimeOut == WAIT_TIMEOUT)
	{
		TerminateThread(m_hDigiSignCheck,0);
		m_hDigiSignCheck = NULL;
		CloseHandle(m_hDigiSignCheck);
		return 0x01;
	}
	return dwRetValueThread;
}

DWORD CPolymorphicVirus::CheckIsTrustedDigiCert(LPCTSTR m_szFile2Check)
{
	DWORD	dwRetValue = 0x00;

	dwRetValue = VerifySignature(m_szFile2Check);


	return dwRetValue;
}

DWORD CPolymorphicVirus::VerifySignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;
	//bool bValid = false;
	DWORD dwValid = 0x00;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:
    
    1) The certificate used to sign the file chains up to a root 
    certificate located in the trusted root certificate store. This 
    implies that the identity of the publisher has been verified by 
    a certification authority.
    
    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the  
    end entity certificate is stored in the trusted publisher store,  
    implying that the user trusts content from this publisher.
    
    3) The end entity certificate has sufficient permission to sign 
    code, as indicated by the presence of a code signing EKU or no 
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    
    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);
	//TCHAR szLog[MAX_PATH] = {0};
	switch (lStatus) 
    {
        case ERROR_SUCCESS:
            /*
            Signed file:
                - Hash that represents the subject is trusted.

                - Trusted publisher without any verification errors.

                - UI was disabled in dwUIChoice. No publisher or 
                    time stamp chain errors.

                - UI was enabled in dwUIChoice and the user clicked 
                    "Yes" when asked to install and run the signed 
                    subject.
            */
    
//			bValid = true;
			dwValid = 0x01;
            break;
        
        case TRUST_E_NOSIGNATURE:
            // The file was not signed or had a signature 
            // that was not valid.

            // Get the reason for no signature.
            dwLastError = GetLastError();
            if (TRUST_E_NOSIGNATURE == dwLastError ||
                    TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                    TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
            {
                // The file was not signed.
            } 
            else 
            {
                // The signature was not valid or there was an error 
                // opening the file.
            }

            break;

        case TRUST_E_EXPLICIT_DISTRUST:
            // The hash that represents the subject or the publisher 
            // is not allowed by the admin or user.
            break;

        case TRUST_E_SUBJECT_NOT_TRUSTED:
            // The user clicked "No" when asked to install and run.
            break;

        case CRYPT_E_SECURITY_SETTINGS:
            /*
            The hash that represents the subject or the publisher 
            was not explicitly trusted by the admin and the 
            admin policy has disabled user trust. No signature, 
            publisher or time stamp errors.
            */
            break;

        default:
            // The UI was disabled in dwUIChoice or the admin policy 
            // has disabled user trust. lStatus contains the 
            // publisher or time stamp chain error.
            break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return dwValid;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanPolyMorphicEx
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS / REPAIR_FAILED / VIRUS_NOT_FOUND / VIRUS_FILE_DELETE / VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ruapli Sonawane + Anand Shrivastava + Virus Analysis Team
	Description		: Defines the exported functions for the DLL application
--------------------------------------------------------------------------------------*/
DWORD CPolymorphicVirus::CleanPolyMorphicEx(LPTSTR pVirusName, bool bClean)
{	
	DWORD dwStartTime = GetTickCount();
	if(bClean)
		m_dwNoOfFilesRepaired++;
	else
		m_dwNoOfFilesScanned++;

	DWORD dwRetValue = SCAN_ACTION_CLEAN;
	
	dwRetValue = CheckForVirus(bClean);
	if(dwRetValue)
	{
		_tcscpy_s(pVirusName, MAX_VIRUS_NAME, m_pPolyBase->m_szVirusName);
	}
	
	//false means only detect and true means detect and Repair(disinfect)
	if(true == bClean && dwRetValue == SCAN_ACTION_REPAIR)		
	{
		dwRetValue = REAPIR_STATUS_FAILURE; 
		if(m_pPolyBase->CleanVirus())
		{
			dwRetValue = REAPIR_STATUS_SUCCESS;
			/*if(!objMaxPEFile.ValidateFile())
			{
				dwRetValue = REAPIR_STATUS_CORRUPT;
			}*/
		}	
	}
	if(bClean)
		m_dwTotalRepairTime += (GetTickCount() - dwStartTime);
	else
		m_dwTotalScanTime += (GetTickCount() - dwStartTime);
	return dwRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForVirus
	In Parameters	: bool bClean (Detection only or Clean-Repair action)
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: 1 : This function is main scanning handler for different types of viruses.
					  2 : Also manages the scanning flow using current version of REV_ID_TYPE.
--------------------------------------------------------------------------------------*/
DWORD CPolymorphicVirus::CheckForVirus(bool bClean)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	TCHAR	szLogLine[1024] = {0x00};

	if(!m_pMaxPEFile->m_byVirusRevIDs)
	{
		return iRetStatus;
	}
	
	m_pPolyBase = new CPolyInrar(m_pMaxPEFile);
	iRetStatus = m_pPolyBase->DetectVirus();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	delete m_pPolyBase;
	m_pPolyBase = NULL;

	if(!m_pMaxPEFile->m_bPEFile)
	{
		return iRetStatus; 
	}

	m_pPolyBase = new CPolyNeshta(m_pMaxPEFile);
	iRetStatus = m_pPolyBase->DetectVirus();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	delete m_pPolyBase;
	m_pPolyBase = NULL;

	m_pPolyBase = new CPolyBase(m_pMaxPEFile);
	if(!m_pPolyBase->HighLevelDetection())
	{
		return iRetStatus;
	}
	delete m_pPolyBase;
	m_pPolyBase = NULL;
	
	struct
	{
		WORD wVirusRevID;
		CPolyBase *pPolyBase;
		BYTE bOldRevID;
		bool bScan;
	}pVirusList[] = 
	{	
		{NONREPAIRABLE_REV_ID, new CNonRepairable(m_pMaxPEFile, m_pFileName)},
		{PACKERS_REV_ID, new CPackers(m_pMaxPEFile)},
		{TROJANS_REV_ID, new CTrojans(m_pMaxPEFile)},
		{SEMIPOLYTROJANS_REV_ID, new CSemiPolyTrojans(m_pMaxPEFile)},
		//{POLYFUNLOVE_REV_ID, new CPolyFUNLOVE(m_pMaxPEFile)},
		//{POLYVBHN_REV_ID, new CPolyVBHN(m_pMaxPEFile)},
		//{POLYAGENTES_REV_ID, new CPolyAgentES(m_pMaxPEFile)},
		{POLYSGENERICKDZ_REV_ID, new CPolyTrojangenerickdz(m_pMaxPEFile)},
		{POLYSWISYNBNER_REV_ID, new CPolyTrojanSwisynBNER(m_pMaxPEFile)},
		{POLYBANKERBANBRA_REV_ID, new CPolyBankerBanbra(m_pMaxPEFile)},
		{POLYZBOTWTEN_REV_ID, new CPolyZbotwten(m_pMaxPEFile)},
		{POLYDOWNLOADERH_REV_ID, new CPolyDownloaderH(m_pMaxPEFile)},
		{POLYGENKD30602080_REV_ID, new CPolyTrojanGenKD30602080(m_pMaxPEFile)},
		{POLYDELFX_REV_ID, new CPolyDelfx(m_pMaxPEFile)},
		//{LAMEREL_REV_ID, new CPolyLamerEL(m_pMaxPEFile)},//For Crash Checking
		{POLYSWISYNFOHA_REV_ID, new CPolySWISYNFOHA(m_pMaxPEFile)},
		{POLYBITMINER_REV_ID, new CPolyRiskToolBitMiner(m_pMaxPEFile)},
		{POLYBLOOREDE_REV_ID, new CPolyBLOOREDE(m_pMaxPEFile)},
		//{POLAUTORUNVX_REV_ID, new CPolyWormAutorunVX(m_pMaxPEFile)},
		{POLYZUSY22271_REV_ID, new CPolyZusy22271(m_pMaxPEFile)},
		//{POLYINFECTOR_REV_ID, new CPolyInfector(m_pMaxPEFile)},
		{POLYHEURGEN_REV_ID, new CPolyHEURGEN(m_pMaxPEFile)},
		{POLYBITMINERMADAM_REV_ID, new CPolyRiskToolBitMinerMadam(m_pMaxPEFile)},
		{POLYIZUSY256811_REV_ID, new CPolyTrojanZusy256811(m_pMaxPEFile)},
		{AGENTFT_REV_ID, new CPolyAgentFT(m_pMaxPEFile)},
		{POLYGODOGA_REV_ID, new CPolyGodogA(m_pMaxPEFile)},
		{POLYVBGN_REV_ID, new CPolyVBGN(m_pMaxPEFile)},
		{POLYYAKA_REV_ID, new CPolyYakA(m_pMaxPEFile)},
		{FLYSTDIO_REV_ID, new CPolyFlyStdio(m_pMaxPEFile)}, //Emulator
		{PARTRIOT_REV_ID, new CPolyPartriot(m_pMaxPEFile)},
		{MERINOS_REV_ID, new CPolyMerinos(m_pMaxPEFile)},
		{ALCAUL_REV_ID, new CPolyAlcaul(m_pMaxPEFile)},
		{ZAPROM_REV_ID, new CPolyZapRom(m_pMaxPEFile)},
		{KANBAN_REV_ID, new CPolyKanban(m_pMaxPEFile)},
		{VB_REV_ID, new CPolyVB(m_pMaxPEFile)},
		{EVOL_REV_ID, new CPolyEvol(m_pMaxPEFile)},
		{DEVIR_REV_ID, new CPolyDevir(m_pMaxPEFile)},
		{MABEZAT_REV_ID, new CPolyMabezat(m_pMaxPEFile)},
		{SFCER_REV_ID, new CPolySfcer(m_pMaxPEFile)},
		{MOGUL_REV_ID, new CPolyMogul(m_pMaxPEFile)},
		{MINIT_REV_ID, new CPolyMinit(m_pMaxPEFile, m_pFileName)},
		{ELKERN_REV_ID, new CPolyElkern(m_pMaxPEFile)},
		{CENSOR_REV_ID, new CPolyCensor(m_pMaxPEFile)},
		{EXPIRO_REV_ID, new CPolyExpiro(m_pMaxPEFile)}, //Emulator
		{NIMNUL_REV_ID, new CPolyNimnul(m_pMaxPEFile)},
		{FOSFORO_REV_ID, new CPolyFosforo(m_pMaxPEFile)},
		{SWADUK_REV_ID, new CPolySwaduk(m_pMaxPEFile)},
		{KILLFILE_REV_ID, new CPolyKillFile(m_pMaxPEFile)},
		{DUDRA_REV_ID, new CPolyDudra(m_pMaxPEFile)},
		{TROJANPATCHED_REV_ID, new CPolyTrojanPatched(m_pMaxPEFile)},
		{SILCER_REV_ID, new CPolySilcer(m_pMaxPEFile)},
		//{CHITON_REV_ID, new CPolyChiton(m_pMaxPEFile)},
		{DOSER_REV_ID, new CPolyDoser(m_pMaxPEFile)},
		{THORIN_REV_ID, new CPolyThorin(m_pMaxPEFile)},
		{JUNKCOMP_REV_ID, new CPolyJunkComp(m_pMaxPEFile)},		
		{ZMORPH_REV_ID, new CPolyZMorph(m_pMaxPEFile)},
		{AOC_REV_ID, new CPolyAOC(m_pMaxPEFile)},
		{KORU_REV_ID, new CPolyKoru(m_pMaxPEFile)},
		{INVICTUS_REV_ID, new CPolyInvictus(m_pMaxPEFile)},
		{CHAMP_REV_ID, new CPolyChamp(m_pMaxPEFile)},
		{LEVI_REV_ID, new CPolyLevi(m_pMaxPEFile)},
		{ZPERM_REV_ID, new CPolyZperm(m_pMaxPEFile)},
		{LAZYMIN_REV_ID, new CPolyLazyMin(m_pMaxPEFile)},
		{ALMAN_REV_ID, new CPolyAlman(m_pMaxPEFile)},
		{CALM_REV_ID, new CPolyCalm(m_pMaxPEFile)},//50
		{DEADCODE_REV_ID, new CPolyDeadCode(m_pMaxPEFile)},
		{PARITE_REV_ID, new CPolyParite(m_pMaxPEFile)},
		{AFGAN_REV_ID, new CPolyAfgan(m_pMaxPEFile)},
		{DUNDUN_REV_ID, new CPolyDundun(m_pMaxPEFile)},
		{DETNAT_REV_ID, new CPolyDetnat(m_pMaxPEFile)},
		{LAMT_REV_ID, new CPolyLAMT(m_pMaxPEFile)},
		{DELIKON_REV_ID, new CPolyDelikon(m_pMaxPEFile)},
		{POLIP_REV_ID, new CPolyPolip(m_pMaxPEFile)},
		{PAYBACK_REV_ID, new CPolyPayBack(m_pMaxPEFile)},
		{SATIR_REV_ID, new CPolySatir(m_pMaxPEFile)},
		//{OPORTO_REV_ID, new CPolyOporto(m_pMaxPEFile)},
		{KENSTON_REV_ID, new CPolyKenston(m_pMaxPEFile)},
		{ALMA_REV_ID, new CPolyAlma(m_pMaxPEFile)},
		{TDSS_REV_ID, new CPolyTDSS(m_pMaxPEFile)},
		//{HEZHI_REV_ID, new CPolyHezhi(m_pMaxPEFile)},
		{BLUWIN_REV_ID, new CPolyBluwin(m_pMaxPEFile)},
		{SMASH_REV_ID, new CPolySmash(m_pMaxPEFile)},
		{FONO_REV_ID, new CPolyFono(m_pMaxPEFile)},
		{SPIKER_REV_ID, new CPolySpiker(m_pMaxPEFile)},
		{DION_REV_ID, new CPolyDion(m_pMaxPEFile)},//68
		{POLYK_REV_ID, new CPolyPolyk(m_pMaxPEFile)},
		{JOLLA_REV_ID, new CPolyJolla(m_pMaxPEFile)},
		{DIEHARD_REV_ID, new CPolyDieHard(m_pMaxPEFile)},
		{HATRED_REV_ID, new CPolyHatred(m_pMaxPEFile)},
		{VULCAS_REV_ID, new CPolyVulcas(m_pMaxPEFile)},
		{ZERO_REV_ID, new CPolyZero(m_pMaxPEFile)},
		{LUNA_REV_ID, new CPolyLuna(m_pMaxPEFile)},
		{ZPERMORPH_REV_ID, new CPolyZperMorph(m_pMaxPEFile)},
		{MARBURG_REV_ID, new CPolyMarburg(m_pMaxPEFile)},
		{XTAIL_REV_ID, new CPolyXtail(m_pMaxPEFile)},
		{CRUNK_REV_ID, new CPolyCrunk(m_pMaxPEFile)},
		{INDUC_REV_ID, new CPolyInduc(m_pMaxPEFile)},
		{FIASKO_REV_ID, new CPolyFiasko(m_pMaxPEFile)},
		{RUBASHKA_REV_ID, new CPolyRubashka(m_pMaxPEFile)},
		{AGENTCE_REV_ID, new CPolyAgentCE(m_pMaxPEFile)},
		{HPS_REV_ID, new CPolyHPS(m_pMaxPEFile)},
		{XORER_REV_ID, new CPolyXorer(m_pMaxPEFile)},
		{IMPLINKER_REV_ID, new CPolyImplinker(m_pMaxPEFile)},
		{KARACHUN_REV_ID, new CPolyKarachun(m_pMaxPEFile)},
		{CHOP_REV_ID, new CPolyChop(m_pMaxPEFile)},
		{BYTESV_REV_ID, new CPolyBytesv(m_pMaxPEFile)},
		{DUGERT_REV_ID, new CPolyDugert(m_pMaxPEFile)},
		{POSON4367_REV_ID, new CPolyPoson4367(m_pMaxPEFile)},
		{MEGINA_REV_ID, new CPolyMeginA(m_pMaxPEFile)},
		{EXPIRO64_REV_ID, new CPolyExpiro64(m_pMaxPEFile)},
		{POLYTROJANS64_REV_ID, new CPolyTrojans64(m_pMaxPEFile)},//102
												
		// Patched call viruses
		{CRAZYPRIER_REV_ID, new CPolyCrazyPrier(m_pMaxPEFile)},
		{HIV_REV_ID, new CPolyHIV(m_pMaxPEFile)},
		{SUPERTHREAT_REV_ID, new CPolySuperThreat(m_pMaxPEFile)},
		{BASKET_REV_ID, new CPolyBasket(m_pMaxPEFile)},
		{GREMO_REV_ID, new CPolyGremo(m_pMaxPEFile)},
		{BABYLONIA_REV_ID, new CPolyBabylonia(m_pMaxPEFile)},
		{BOLZANO_REV_ID, new CPolyBolzano(m_pMaxPEFile)},
		{ETAP_REV_ID, new CPolyETap(m_pMaxPEFile)},
		{YOUNGA_REV_ID, new CPolyYounga(m_pMaxPEFile)},
		{RAINSONG_REV_ID, new CPolyRainSong(m_pMaxPEFile)},
		
		// Semi Polymorphic viruses 
		{DEEMO_REV_ID, new CPolyDeemo(m_pMaxPEFile)},
		{LAMER_REV_ID, new CPolyLamer(m_pMaxPEFile)},
		{MKAR_REV_ID, new CPolyMkar(m_pMaxPEFile)},
		{TYHOS_REV_ID, new CPolyTyhos(m_pMaxPEFile)},
		{IPAMOR_REV_ID, new CPolyIpamor(m_pMaxPEFile)},
		{SPIT_REV_ID, new CPolySpit(m_pMaxPEFile)},
		{PIONEER_REV_ID, new CPolyPioneer(m_pMaxPEFile)},
		{INITX_REV_ID, new CPolyInitx(m_pMaxPEFile)},
		{WIDE_REV_ID, new CPolyWide(m_pMaxPEFile)},
		{GYPET_REV_ID, new CPolyGypet(m_pMaxPEFile)},
		{INTA_REV_ID, new CPolyInta(m_pMaxPEFile)},
		{BLUBACK_REV_ID, new CPolyBluback(m_pMaxPEFile)},		
		{UNDERTAKER_REV_ID, new CPolyUndertaker(m_pMaxPEFile)},		
		{MIMIX_REV_ID, new CPolyMimix(m_pMaxPEFile)},		//Emulator
		{PADANIA_REV_ID, new CPolyPadania(m_pMaxPEFile)},		
		{HIGHWAYB_REV_ID, new CPolyHighway(m_pMaxPEFile)},		
		{FUJACK_REV_ID, new CPolyFujack(m_pMaxPEFile)},		
		{CAW_REV_ID, new CPolyCaw(m_pMaxPEFile)},		
		{GINRA_REV_ID, new CPolyGinra(m_pMaxPEFile)},		
		{GODOG_REV_ID, new CPolyGodog(m_pMaxPEFile)},	
		{DZAN_REV_ID, new CPolyDzan(m_pMaxPEFile)},	
		{ASSILL_REV_ID, new CPolyAssill(m_pMaxPEFile)},	
		{DOWNLOADERTOLSTYA_REV_ID, new CPolyDownloaderTolstyA(m_pMaxPEFile)},	
		{ALIMIK_REV_ID, new CPolyAlimik(m_pMaxPEFile)},	
		{NUMROCK_REV_ID, new CPolyNumrock(m_pMaxPEFile)},	
		{MIAM_REV_ID, new CPolyMiam(m_pMaxPEFile)},	
		{SEMISOFT_REV_ID, new CPolyHllpSemisoft(m_pMaxPEFile)},	
		{GLORIA_REV_ID, new CPolyGloria(m_pMaxPEFile)},	
		{VBITL_REV_ID, new CPolyVBITL(m_pMaxPEFile)},	
		{GAMETHIEFLMIROA_REV_ID, new CPolyGameThiefLmirOA(m_pMaxPEFile)},	
		{POLYKURGAN_REV_ID, new CPolyKurgan(m_pMaxPEFile)},	
		{TABECI_REV_ID, new CPolyTabeci(m_pMaxPEFile)},	
		{KUTO_REV_ID, new CPolyKuto(m_pMaxPEFile)},
		{DROPPERDAPATOAZUE_REV_ID, new CPolyDropperDapatoAZUE(m_pMaxPEFile)},
		{JETHRO_REV_ID, new CPolyJethro(m_pMaxPEFile)},		
		{SPINEX_REV_ID, new CPolySpinex(m_pMaxPEFile)},		
		{MEMORIAL_REV_ID, new CPolyMemorial(m_pMaxPEFile)},	
		{OPORTO_REV_ID, new CPolyOporto(m_pMaxPEFile)},//149
		{EAK_REV_ID, new CPolyEak(m_pMaxPEFile)},
		{NATHAN_REV_ID, new CPolyNathan(m_pMaxPEFile)},
		{MAMIANUNEIF_REV_ID, new CPolyMamianuneIf(m_pMaxPEFile)},
		{LMIRWJ_REV_ID, new CPolyGameThiefLmirWJ(m_pMaxPEFile)},
		{VIKING_REV_ID, new CPolyViking(m_pMaxPEFile)},//154
		{RANSOM_REV_ID, new CPolyRansom(m_pMaxPEFile)}, //Emulator155
		{PATCHEDQR_REV_ID, new CPolyPatchedQr(m_pMaxPEFile)},
		{PATCHEDQW_REV_ID, new CPolyPatchedQw(m_pMaxPEFile)},
		{TENGA_REV_ID, new CPolyTenga(m_pMaxPEFile)},
		{RECONYC_REV_ID, new CPolyReconyc(m_pMaxPEFile)},
		{MEWSPY_REV_ID, new CPolyMEWSPY(m_pMaxPEFile)},
		{POLYINF_REV_ID, new CPolyInfector(m_pMaxPEFile)},
		{POLYAGENT_REV_ID, new CPolyAgent(m_pMaxPEFile)},
		{POLYDETROIE_REV_ID, new CPolyVirusHLLPDeTroie(m_pMaxPEFile)},
		{POLYINFECTORGEN_REV_ID, new CPolyInfectorGen(m_pMaxPEFile)},
		{POLYILAMERFG_REV_ID, new CPolyLAMERFG(m_pMaxPEFile)},
		{POLYIHOROPED_REV_ID, new CPolyHOROPED(m_pMaxPEFile)},
		{POLYIHOROPEI_REV_ID, new CPolyHOROPEI(m_pMaxPEFile)},
		//{FEARSO_REV_ID, new CPolyFearso(m_pMaxPEFile)},
		{POLYAGENTRC4_REV_ID, new CPolyTrojanAgentRC4(m_pMaxPEFile)},
		{POLYSHOHDI_REV_ID, new CPolyVirusShohdi(m_pMaxPEFile)},
		{VIKINGEO_REV_ID, new CPolyWormVikingEO(m_pMaxPEFile)},
		{POLYSHODIA_REV_ID, new CPolyVirusShodiA(m_pMaxPEFile)},
		{TROJNPATCHEDRW_REV_ID, new CPolyPatchedRW(m_pMaxPEFile)},
		
		// Viruses using Emulator
		{SALITY_REV_ID, new CPolySality(m_pMaxPEFile)},
		{PADDI_REV_ID, new CPolyPaddi(m_pMaxPEFile)},
		{XPAJ_REV_ID, new CPolyXpaj(m_pMaxPEFile)},
		{XPAJA_REV_ID, new CPolyXpajA(m_pMaxPEFile)},
		{TVIDO_REV_ID, new CPolyTvido(m_pMaxPEFile)},
		{DRILLER_REV_ID, new CPolyDriller(m_pMaxPEFile)},//178
		{ANDRAS_REV_ID, new CPolyAndras(m_pMaxPEFile)},
		////{CTX_REV_ID, new CPolyCTX(m_pMaxPEFile)},
		{ARIS_REV_ID, new CPolyAris(m_pMaxPEFile)},
		{KRIZ_REV_ID, new CPolyKriz(m_pMaxPEFile)},
		{HALEN_REV_ID, new CPolyHalen(m_pMaxPEFile)},
		{MODRIN_REV_ID, new CPolyModrin(m_pMaxPEFile)},
		{VAMPIRO_REV_ID, new CPolyVampiro(m_pMaxPEFile)},
		
		//Heuristics detection
		{HEURISTIC_REV_ID, new CPolyHeuristics(m_pMaxPEFile)},
		//{SEMIPOLYTROJANS_REV_ID, new CSemiPolyTrojans(m_pMaxPEFile)}
		{VIRUT_REV_ID, new CPolyVirut(m_pMaxPEFile, bClean)}
	};
	
	if(m_pMaxPEFile->m_byVirusRevIDs[LOBYTE(GR0_REV_ID.u.wRevID)] != HIBYTE(GR0_REV_ID.u.wRevID))
	{
		memset(m_pMaxPEFile->m_byVirusRevIDs, 0, 16);
		m_pMaxPEFile->m_byVirusRevIDs[LOBYTE(GR0_REV_ID.u.wRevID)] = HIBYTE(GR0_REV_ID.u.wRevID);
	}

	int i = 0;
	for(; i < _countof(pVirusList); i++)
	{
		if(m_pMaxPEFile->m_byVirusRevIDs[LOBYTE(pVirusList[i].wVirusRevID)] != HIBYTE(pVirusList[i].wVirusRevID))
		{
			if	(pVirusList[i].pPolyBase && 
				(!m_pMaxPEFile->m_b64bit || LOBYTE(pVirusList[i].wVirusRevID) == LOBYTE(SEMIPOLYTROJANS_REV_ID) || LOBYTE(pVirusList[i].wVirusRevID) == LOBYTE(VIRUT_REV_ID) || LOBYTE(pVirusList[i].wVirusRevID) == LOBYTE(ELKERN_REV_ID) || LOBYTE(pVirusList[i].wVirusRevID) == LOBYTE(EXPIRO64_REV_ID) || LOBYTE(pVirusList[i].wVirusRevID) == LOBYTE(PATCHEDQW_REV_ID)))			
			{
				m_pPolyBase = pVirusList[i].pPolyBase;
				iRetStatus = m_pPolyBase->DetectVirus();
				if(iRetStatus)
				{
					break;
				}

				pVirusList[i].bScan = true;
				delete pVirusList[i].pPolyBase;
				pVirusList[i].pPolyBase = NULL;
			}
		}

		m_pPolyBase = NULL;
	}	
	
	for(int i = 0; i < _countof(pVirusList); i++)
	{
		pVirusList[i].bOldRevID = m_pMaxPEFile->m_byVirusRevIDs[LOBYTE(pVirusList[i].wVirusRevID)]; 
	}

	for(int i = 0; i < _countof(pVirusList); i++)
	{
		m_pMaxPEFile->m_byVirusRevIDs[LOBYTE(pVirusList[i].wVirusRevID)] = HIBYTE(pVirusList[i].wVirusRevID);				
	}

	for(int i = 0; i < _countof(pVirusList); i++)
	{
		if(!pVirusList[i].bScan)
		{
			m_pMaxPEFile->m_byVirusRevIDs[LOBYTE(pVirusList[i].wVirusRevID)] = pVirusList[i].bOldRevID;				
		}
		
		if(pVirusList[i].pPolyBase != m_pPolyBase && pVirusList[i].pPolyBase)
		{
			delete pVirusList[i].pPolyBase;
			pVirusList[i].pPolyBase = NULL;
		}
	}

	return iRetStatus;
}
