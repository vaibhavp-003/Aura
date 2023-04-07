/*======================================================================================
FILE				: Trojans.h
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
NOTES				: This is detection module for different malware (Trojan) Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int SJT_BUFF_SIZE			= 0x2D00;
const int ZACCESS_J_BUFF_SIZE	= 0x200;
const int DIALER_BUFF_SIZE      = 0x2000;
const int RTM_ACCESS_BUFF_SIZE  = 0x300;//added 05-12-2020

typedef bool (*LPFNUnPackUPXFile)(char *pFileName, char *pUnpackFileName, DWORD dwCodeOffset, DWORD dwSigOffset, bool bLZMA);

class CTrojans : public CPolyBase
{
	int     DetectBankerRTM();//added 05-12-2020
	int		DetectKido();
	int		DetectAllaple();
	int		DetectSohanad();
	int		DetectPoison();
	int		DetectZAccess();
	int		DetectJorrik();
	int		DetectCosmu();
	int		DetectCosmuALWB();
	int		DetectEGDial();
	int		DetectInstallCoreBrj();
	int		DetectSwizzor();
	int		DetectGenomeDLL();
	int		DetectTrojanMonderA();
	int		DetectPackedPolyCrypt();
	int		DetectKlone();
	int		DetectAgentBCN();
	int		DetectBlackA();
	int		DetectSmartFortress();
	int		DetectDCodecPackSJT();
	int		DetectTrojanAutorunDM();
	int		DetectPackedKrapIU();
	int		DetectLpler();
	int     DetectDialerCJ();
	int		DetectMufanomAQDA();
	int		DetectMudropASJ();
	int		DetectInstallCoreA();
	int		DetectFrauDropXYRW();
	int		DetectChifraxD();
	int		DetectObfuscatedGen();
	int		DetectOnlineGameAndWOWMagania();
	int		DetectAgentCWA();
	int		DetectSytro();
	int		DetectSefnit();
	int		DetectShiz();
	int		DetectDownloaderTibs();
	int		DetectSinowal();
	int		DetectTepfer();	
	int		DetectWebWatcher();	
	int		DetectSmallVQ();	
	int		DetectWLordgen();	
	int		DetectPswRuftarHtm();
	int		DetectSafeDecisionINC();
	int		DetectLoadMoney();
	int		DetectMonderd();
	int		DetectAgentXcfc();
	int		DetectQhostsBm();
	int		DetectSolimba();
	int		DetectVittaliaInstaller();
	int		DetectCinmusAIZH();
	int		DetectOptimumInstaller();
	int		DetectSpector();
	int		DetectMedfos();
	int		DetectDNSChangerHD();
	int		DetectPackedCpex();
	int		DetectPalevo();
	int		DetectPSWKatesC();
	int		DetectSinowalEEE();
	int		DetectKatushaQ();
	int		DetectGLDCT();
	int		DetectBackDoorLavanDos();
	int		DetectDiamin();
	int		DetectShipUp();
	int		DetectMorstar();
	int		DetectYakes();
	int		DetectFiseria();
	int		DetectNGRBot();
	int		DetectOteZinuDl();
	int		DetectFlyStudio();
	int		DetectAutoitAZA();
			
	bool    CheckBankerRTM();//added 05-12-2020
	bool	GetPoisonSig(DWORD dwSig1Off, DWORD dwSig3Off, DWORD dwSigOff);
	bool	UnPackUPXFile(LPTSTR szTempFilePath);
	void	GetTempFilePath(LPTSTR szFileName);
	bool	DetectCodecPackSJT1();
	bool	DetectCodecPackSJT2();
	bool	DetectCodecPackSJT3();
	int		DecryptAutorunDM(int iOp, DWORD dwKey);
	bool	DetectZAccessC();
	bool	DetectZAccessJ();
	bool	DetectZAccessE();
	bool	DetectZAccessG();	
	bool	DetectZAccessH();
	bool	DetectZAccessL();
	bool    DetectDialerCJSig(DWORD dwOffset,DWORD dwOverlayChk);
	bool	CheckSytroSig(DWORD dwReadOffset);
	

public:
	static LPFNUnPackUPXFile	m_lpfnUnPackUPXFile;
	static HMODULE				m_hUPXUnpacker;	

	CTrojans(CMaxPEFile *pMaxPEFile);
	~CTrojans(void);

	int		DetectVirus();
};
