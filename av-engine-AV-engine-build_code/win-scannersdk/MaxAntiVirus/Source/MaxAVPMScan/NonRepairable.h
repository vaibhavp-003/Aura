/*======================================================================================
FILE				: NonRepairable.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for Non-repairable malwares.
					  The repair action is : DELETE
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int IDELE_BUFF_SIZE 		= 0x60;
const int BACAVER_LOOP_SZ 		= 0x40;
const int LORD_PE_BUFF_SIZE		= 0x100;
const int MAX_KME_BUFF_SIZE		= 0x2000;
const int STEPAR_BUFF_SIZE		= 0x10000;
const int LEGACY_BUFF_SIZE		= 0x100;
const int CRYPTO_BUFF_SIZE = 0x200;

#define REGSVR _T("\\regsvr.exe")

class CNonRepairable: public CPolyBase
{	
	LPCTSTR m_pFileName;
	BYTE	m_bySig;
	
	int		DetectSmalli();
	int		DetectPECorrupt();
	int		DetectIdele();
	int		DetectBakaver();
	int		DetectLordPE();
	int		DetectKME();
	int		DetectStepar();
	int		DetectKrap();
	int		DetectCrypto();
	int		DetectCivut();
	int		DetectLom();
	int		DetectMental();
	int		DetectBayan();
	int		DetectAldebaran();
	int		_DetectAldebaran();
	int		DetectBlaken();
	int		DetectLegacy();
	int		DetectGolem();
	int		DetectFunloveDam();
	int		DetectKaze();
	int		DetectSankei();
	int		DetectEnerlam();
	int		DetectTick();
	int		DetectTolone();
	int		DetectVulcano();
	int		DetectNakuru();
	int		DetectGobi();
	int		DetectRufis();
	int		DetectDroworC();
	int		DetectXorer();
	int		DetectNGVCK();
	int		DetectDockA();
	int		DetectVB();
	int		DetectDream();
	int		DetectSuperThreat();
	int		DetectDelf();
	int		DetectSmall98();
	int		DetectTwinny();
	int		DetectAgentJ();
	int		DetectHarrier();
	int		DetectRedlofA();
	int		DetectZMorph2784();
	int		DetectZMorph();
	int		DetectMosquitoC();
	int		DetectIkatA();
	int		DetectGlyn();
	int		DetectDurchinaA();
	int		DetectIframerC();
	int		DetectVBZ();
	int		DetectVirusArisG();
	int		DetectVirusTexelK();
	int		DetectVBAZ();
	int		DetectVbAA();
	int		DetectSalityK();
	int		DetectDelfB();
	int		DetectDecon();
	//int		DetectInfinite();
	int		DetectInfector();
	int		DetectVBCC();
	int		DetectBolzanoGen();
	int		DetectBubeG();
	int		DetectHLLWVBA();
	int		DetectHLLWVBS();
	int		DetectHLLPLaboxA();
	int		DetectXorerA();
	int		DetectHLLO28672();
	int		DetectHLLWMintopA();
	int		DetectHLLWProdvin();
	int		DetectHLLWRologC();
	int		DetectHLLWRandir();

	int		DetectWLKSM();
	int		DetectFontraA();
	int		DetectCargo();
	int		DetectLamerKL();
	int		DetectLevi();
	int		DetectSantana();
	int		DetectVBCS();
	int		DetectVBBT();
	int		DetectVBCM();
	int		DetectVBCR();
	int		DetectVBGP();
	int		DetectVBK();
	int		DetectVBLP();
	int		DetectLevi3205();
	int		DetectPesinA();
	int		DetectSalityATBH();
	int		DetectVBC();
	int		DetectXbotor();
	int		DetectMezq();
	int		DetectProjet2649();
	int		DetectSmallN();
	int		DetectVBBC();
	int		DetectVBBG();
	int		DetectVBhq();
	int		DetectVBU();
	int		DetectXorerBH();
	int		DetectXorerEA();
	int		DetectAgentCH();
	int		DetectHLLOMomacA();
	int		DetectHLLP41472e();
	int		DetectSantana1104();
	int		DetectVBEL();
	int		DetectVBEY();
	int		DetectXorerei();
	int		DetectVBV();
	int		DetectAlmanD();
	int		DetectKateB();
	int		DetectMipisA();
	int		DetectVBKH();

	


	int		_DetectTwinny();
	bool	GetBakaverParam();
	bool	GetKMESigByte();
	bool	SearchKMEByteSig();
	bool	GetKMESigByteStartOffset(DWORD &dwSigStart);
	bool	GetBlakenAParam();
	bool	GetLegacyParam(DWORD dwJmp);
	

public:

	CNonRepairable(CMaxPEFile *pMaxPEFile, LPCTSTR pFilename);
	~CNonRepairable(void);

	int		DetectVirus();
};


