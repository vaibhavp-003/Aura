/*======================================================================================
FILE				: SemiPoly.h
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
CREATION DATE		: 12 Jun 2013
NOTES				: This is detection module for malware using * base detection pattern.
					  Aho-corasick binary seraching is used to fasten the detection 
					  It is the collection of different malwares for which we use Aho-corasick 
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#pragma comment(lib,"version")

#include "polybase.h"

class CPolyDeemo : public CPolyBase
{
	DWORD m_dwCallAddr;
	DWORD m_dwOriPatchOffset;

public:
	CPolyDeemo(CMaxPEFile *pMaxPEFile);
	~CPolyDeemo(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyLamer : public CPolyBase
{
	DWORD	m_dwOriginalFileOffset;	
	DWORD	m_dwOriginalFileSize;
public:
	CPolyLamer(CMaxPEFile *pMaxPEFile);
	~CPolyLamer(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyMkar : public CPolyBase
{
	DWORD m_dwReplaceOffset;

public:
	CPolyMkar(CMaxPEFile *pMaxPEFile);
	~CPolyMkar(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyTyhos : public CPolyBase
{
public:
	CPolyTyhos(CMaxPEFile *pMaxPEFile);
	~CPolyTyhos(void);

	int DetectVirus(void);
};

class CPolyIpamor : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwTruncateSize;

public:
	CPolyIpamor(CMaxPEFile *pMaxPEFile);
	~CPolyIpamor(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

const int ORIGINAL_FILE_OFFSET = 0x2000;

class CPolySpit : public CPolyBase
{	
public:
	CPolySpit(CMaxPEFile *pMaxPEFile);
	~CPolySpit(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyNeshta : public CPolyBase
{
	DWORD	m_dwReplaceOffset;
	
	int		DisinfectNeshta(bool bDetectOnly = false);

public:
	CPolyNeshta(CMaxPEFile *pMaxPEFile);
	~CPolyNeshta(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class CPolyInitx : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwFillZeroOff;
public:
	CPolyInitx(CMaxPEFile * pMaxPEFile);
	~CPolyInitx(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyWide : public CPolyBase
{
	DWORD m_dwCalloffset;
	typedef enum WIDE_INFECTION_TYPE 
	{
		WIDE_7910,
		WIDE_8135_A
	};
	WIDE_INFECTION_TYPE m_eInfectionType;

public:
	CPolyWide(CMaxPEFile * pMaxPEFile);
	~CPolyWide(void);

	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolyGypet : public CPolyBase
{
	DWORD m_dwCalloffset;
	DWORD m_dwFillZeroOff;

public:
	CPolyGypet(CMaxPEFile * pMaxPEFile);
	~CPolyGypet(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyInta : public CPolyBase
{
	DWORD m_dwCallAddr;
	
public:
	CPolyInta(CMaxPEFile *pMaxPEFile);
	~CPolyInta(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolyBluback : public CPolyBase
{	
	DWORD m_dwPatchAEPMapped;

public:
	CPolyBluback(CMaxPEFile *pMaxPEFile);
	~CPolyBluback(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyUndertaker : public CPolyBase
{
  	DWORD m_dwOriginalAEP;

public:
	CPolyUndertaker(CMaxPEFile * pMaxPEFile);
	~CPolyUndertaker(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyMimix : public CPolyBase
{	
public:
	CPolyMimix(CMaxPEFile *pMaxPEFile);
	~CPolyMimix(void);
	
	int DetectVirus(void);
	int CleanVirus(void);	
};

class CPolyPadania : public CPolyBase
{	
	DWORD m_dwFileEndOff;

public:
	CPolyPadania(CMaxPEFile *pMaxPEFile);
	~CPolyPadania(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyHighway : public CPolyBase
{
	DWORD m_dwType;
	bool FixImportTable();

public:
	CPolyHighway(CMaxPEFile *pMaxPEFile);
	~CPolyHighway(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyFujack : public CPolyBase
{ 
	DWORD m_dwStratOFfile;
	DWORD m_dwOrifileSize;

	bool FujackParam();

public:
	CPolyFujack(CMaxPEFile *pMaxPEFile);
	~CPolyFujack(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyCaw : public CPolyBase
{
	DWORD m_dwSize;
	DWORD m_dwOrigAEP;

public:
	CPolyCaw(CMaxPEFile *pMaxPEFile);
	~CPolyCaw(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyGinra : public CPolyBase
{
  	DWORD m_dwOriginalAEP;

public:
	CPolyGinra(CMaxPEFile * pMaxPEFile);
	~CPolyGinra(void);

	int DetectVirus(void);
	int CleanVirus(void);
};
	
class CPolyDzan : public CPolyBase
{
  	DWORD m_dwOffset;

public:
	CPolyDzan(CMaxPEFile *pMaxPEFile);
	~CPolyDzan(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyAssill: public CPolyBase
{
	DWORD	m_dwOriFileSize;			
	DWORD	m_dwOriRsrcPRD;			
	DWORD	m_dwOriRsrcRVA;			
	DWORD	m_dwOriRsrcSRD;		
	DWORD	m_dwOriDataSizeAtFileEnd;	
	DWORD	m_dwNTHeaderStartOffset;	
	DWORD	m_dwResourcReplacementOffset;
	DWORD	m_dwRewriteAdd;

	void DecryptAssill();
	void FiXRes(IMAGE_RESOURCE_DIRECTORY *dir, BYTE **root, DWORD delta);

public:
	CPolyAssill(CMaxPEFile *pMaxPEFile);
	~CPolyAssill(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyDownloaderTolstyA : public CPolyBase
{
	DWORD m_dwDecOffset;
  	
public:
	CPolyDownloaderTolstyA(CMaxPEFile *pMaxPEFile);
	~CPolyDownloaderTolstyA(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyAlimik : public CPolyBase
{	
public:
	CPolyAlimik(CMaxPEFile *pMaxPEFile);
	~CPolyAlimik(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyNumrock : public CPolyBase
{
	DWORD m_dwVirusCodeOffset;

public:
	CPolyNumrock(CMaxPEFile *pMaxPEFile);
	~CPolyNumrock(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyMiam : public CPolyBase
{
	DWORD m_dwAEPFileOffset;
	DWORD m_dwVirusCodeOffset;

public:
	CPolyMiam(CMaxPEFile *pMaxPEFile);
	~CPolyMiam(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyHllpSemisoft : public CPolyBase
{
	DWORD dwReplaceOffset;
  
 public:
	CPolyHllpSemisoft(CMaxPEFile * pMaxPEFile);
	~CPolyHllpSemisoft(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyGloria : public CPolyBase
{
	DWORD m_dwOriginalAEP;

public:

	CPolyGloria(CMaxPEFile *pMaxPEFile);
	~CPolyGloria(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyVBITL : public CPolyBase
{
	DWORD m_dwDecOffset;
  
 public:
	CPolyVBITL(CMaxPEFile * pMaxPEFile);
	~CPolyVBITL(void);

	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolyGameThiefLmirOA : public CPolyBase
{
	DWORD m_dwReplaceOff;
	  
 public:
	CPolyGameThiefLmirOA(CMaxPEFile * pMaxPEFile);
	~CPolyGameThiefLmirOA(void);

	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolyKurgan : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwBuffStart;
	DWORD m_dwWriteSize;
	DWORD m_dwImageSize;
	DWORD m_dwTruncateOff;
	  
 public:
	CPolyKurgan(CMaxPEFile * pMaxPEFile);
	~CPolyKurgan(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyTabeci : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	  
 public:
	CPolyTabeci(CMaxPEFile * pMaxPEFile);
	~CPolyTabeci(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyKuto : public CPolyBase
{
	DWORD m_dwOriginalAEP,m_dwImportOffset;
	  
 public:
	CPolyKuto(CMaxPEFile * pMaxPEFile);
	~CPolyKuto(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyDropperDapatoAZUE : public CPolyBase
{
	DWORD m_dwReplaceOff;
	  
 public:
	CPolyDropperDapatoAZUE(CMaxPEFile * pMaxPEFile);
	~CPolyDropperDapatoAZUE(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyJethro : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	  
 public:
	CPolyJethro(CMaxPEFile * pMaxPEFile);
	~CPolyJethro(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolySpinex : public CPolyBase
{	
public:
	CPolySpinex(CMaxPEFile *pMaxPEFile);
	~CPolySpinex(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolyMemorial : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	  
 public:
	CPolyMemorial(CMaxPEFile * pMaxPEFile);
	~CPolyMemorial(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyOporto :	public CPolyBase
{
	DWORD	m_dwVirusStartOffset;
	
public:
	CPolyOporto(CMaxPEFile *pMaxPEFile);
	~CPolyOporto(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolyEak : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwVirusOff;
	
public:
	CPolyEak(CMaxPEFile *pMaxPEFile);
	~CPolyEak(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyNathan : public CPolyBase
{
	DWORD m_dwOriginalAEP;
public:
	CPolyNathan(CMaxPEFile *pMaxPEFile);
	~CPolyNathan(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyMamianuneIf : public CPolyBase
{
	DWORD	m_dwtruncateOffset;
	DWORD	m_dwOverlaySize;
public:
	CPolyMamianuneIf(CMaxPEFile *pMaxPEFile);
	~CPolyMamianuneIf(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class CPolyGameThiefLmirWJ: public CPolyBase
{
	DWORD m_dwReplaceOffset;
  
 public:
	CPolyGameThiefLmirWJ(CMaxPEFile * pMaxPEFile);
	~CPolyGameThiefLmirWJ(void);

	int DetectVirus(void);
	int CleanVirus(void);

};

class CPolyViking : public CPolyBase
{
	DWORD m_dwOverlayStartoff;
public:
	CPolyViking(CMaxPEFile *pMaxPEFile);
	~CPolyViking(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyLamerEL: public CPolyBase
{
	DWORD   m_dwStartOffset;
	DWORD	m_dwFirstSecOffset; 
	DWORD	m_dwOrigFileSize; 
	DWORD	m_dwOrigFileOff;
	BYTE	*m_byDecrypBuff;
	int		 m_iMZCheck;

 public:

	CPolyLamerEL(CMaxPEFile * pMaxPEFile);
	~CPolyLamerEL(void);
	
	int DecryptionLamerEL(DWORD dwDecStart,DWORD dwXorKey);
	int DecryptionLamerEL1(DWORD m_dwOffset);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyPatchedQr : public CPolyBase
{
	DWORD	m_dwOriginalAEP;
	DWORD	m_dwPatchSize;
	DWORD	m_dwPatchStart;

public:
	CPolyPatchedQr(CMaxPEFile *pMaxPEFile);
	~CPolyPatchedQr(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyPatchedQw : public CPolyBase
{
	DWORD	m_dwEggOffset ;
	
public:
	CPolyPatchedQw(CMaxPEFile *pMaxPEFile);
	~CPolyPatchedQw(void);

	int DetectVirus(void);
	int CleanVirus(void);
	bool GetInfo(LPCTSTR ,LPTSTR,LPCTSTR);
};

class CPolyTenga: public CPolyBase
{
	DWORD dwOriAep;
public:
	CPolyTenga(CMaxPEFile *pMaxPEFile);
	~CPolyTenga(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class  CPolyReconyc : public CPolyBase
{
	
	DWORD	m_dwReplaceOffset;
	DWORD	m_dwTruncateSize;
	DWORD	m_dwReplaceOffset1;
		
public:
	CPolyReconyc(CMaxPEFile *pMaxPEFile);
	~CPolyReconyc(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

//Swapnil Sanghai
class CPolyMEWSPY : public CPolyBase
{
	DWORD	m_dwOriginalFileSize;

public:

	CPolyMEWSPY(CMaxPEFile *pMaxPEFile);
	~CPolyMEWSPY(void);
	
	int		DetectVirus(void);
	int		CleanVirus(void);
	
};

//Sneha Kurade + Alisha + Aniket + Sagar
class CPolyInfector : public CPolyBase
{
	DWORD	m_dwOrigAEP;
	DWORD   m_dwCharBuffer;
	BYTE    m_bAEPPatched[0x3C];
	DWORD   m_dwOverlaySize;
	DWORD   m_dwMoveDataSize;
	DWORD   m_dwStratBuff;
	BYTE    bDecryptionKey;
	DWORD   m_dwOriginalAEP;
	DWORD   dwDecrypStart;
	DWORD   m_dwOrigFileOffset;
	int     m_infectorType;   //(1st type infector = 0 , 2nd type = 1)

public:
	CPolyInfector(CMaxPEFile *pMaxPEFile);
	~CPolyInfector(void);

	int DetectVirus(void);
	int CleanVirus(void);
};



//Sneha Kurade
class CPolyAgent: public CPolyBase
{
	DWORD m_dwStartHeader;
	DWORD m_dwOrigHeader;
	DWORD m_dwStratBoundImport;
	DWORD m_dwStartTruncate;
	WORD  m_wNosec;
	
public:
	CPolyAgent(CMaxPEFile *pMaxPEFile);
	~CPolyAgent(void);

         int	DetectVirus(void);
         int	CleanVirus(void);
}; 

//Gaurav Pakhale
class CPolyVirusHLLPDeTroie : public CPolyBase
{

public:
	CPolyVirusHLLPDeTroie(CMaxPEFile *pMaxPEFile);
	~CPolyVirusHLLPDeTroie(void);

	int DetectVirus(void);
	int CleanVirus(void);

	DWORD m_dwOrigFilseSize;

};

//Gaurav Pakhale
class CPolyInfectorGen : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	
public:
	CPolyInfectorGen(CMaxPEFile *pMaxPEFile);
	~CPolyInfectorGen(void);

	int DetectVirus(void);
	int CleanVirus(void);
	
};

//Gaurav Pakhale
class CPolyLAMERFG : public CPolyBase
{
	DWORD m_dwOrigFilseSizeOff;
	DWORD m_dwOrigFilseSize;

public:
	CPolyLAMERFG(CMaxPEFile *pMaxPEFile);
	~CPolyLAMERFG(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};

//Swapnil Sanghai
class CPolyHOROPED : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwOrigFileSize;

public:
	CPolyHOROPED(CMaxPEFile *pMaxPEFile);
	~CPolyHOROPED(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};

//Swapnil Sanghai
class CPolyHOROPEI : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwOrigFileSize;

public:
	CPolyHOROPEI(CMaxPEFile *pMaxPEFile);
	~CPolyHOROPEI(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};

//Sneha Kurade
class CPolyGodogA : public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwDecryptionKey;
	DWORD m_dwFillZeroOff;
	DWORD m_dwStartHeader;
        bool m_GodogType;
	DWORD m_dwStartHeader1;
	DWORD m_dwStartHeader2;

public:
	CPolyGodogA(CMaxPEFile *pMaxPEFile);
	~CPolyGodogA(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

//Sneha Kurade
class CPolyVBGN : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwOrigFileSize;
	DWORD m_dwOverlayStart;

public:
	CPolyVBGN(CMaxPEFile *pMaxPEFile);
	~CPolyVBGN(void);

	int DetectVirus(void);
	int CleanVirus(void);

};

//Sneha Kurade
class CPolyYakA : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwOrigFileSize;
	DWORD m_dwOverlayStart;

public:
	CPolyYakA(CMaxPEFile *pMaxPEFile);
	~CPolyYakA(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

//Gaurav Phalake
class CPolyTrojanZusy256811 : public CPolyBase
{
	DWORD  m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;

public:
	CPolyTrojanZusy256811(CMaxPEFile *pMaxPEFile);
	~CPolyTrojanZusy256811(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

//Sneha Kurade
class CPolyRiskToolBitMinerMadam : public CPolyBase
{
	DWORD	m_dwOrigFileOff;
	DWORD	m_dwOrigFileSize;
	DWORD	dwByteCheck;


public:
	CPolyRiskToolBitMinerMadam(CMaxPEFile *pMaxPEFile);
	~CPolyRiskToolBitMinerMadam(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

//Sneha Kurade
class CPolyHEURGEN : public CPolyBase
{
	DWORD m_dwReplaceOffset;
	DWORD m_dwOrigFileSize;
	

public:
	CPolyHEURGEN(CMaxPEFile *pMaxPEFile);
	~CPolyHEURGEN(void);

	int DetectVirus(void);
	int CleanVirus(void);

};

//Sneha Kurade
class CPolyBLOOREDE : public CPolyBase
{
	DWORD	m_dwOrigFileOff;
	DWORD	m_dwOrigFileSize;
	DWORD	m_dwOrigFileSizeoff;
	DWORD	m_dwExtraByte;

public:
	CPolyBLOOREDE(CMaxPEFile *pMaxPEFile);
	~CPolyBLOOREDE(void);

	int DetectVirus(void);
	int CleanVirus(void);
                
};

//Aniket
class CPolyWormAutorunVX : public CPolyBase
{	
	 DWORD m_dwOrigFileOff;
	 DWORD m_dwOrigFileOffset;
public:
	CPolyWormAutorunVX(CMaxPEFile *pMaxPEFile);
	~CPolyWormAutorunVX(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Gaurav
class CPolyZusy22271 : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;

public:
	CPolyZusy22271(CMaxPEFile *pMaxPEFile);
	~CPolyZusy22271(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Aniket
class  CPolyBankerBanbra : public CPolyBase
{	
	 DWORD m_dwOriginalFileOffset;
	 DWORD dwStartBuff;
	 DWORD m_dwOriginalFileSize;
public:
	CPolyBankerBanbra(CMaxPEFile *pMaxPEFile);
	~CPolyBankerBanbra(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Sagar Bade
class CPolyZbotwten: public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;
	DWORD m_dwReadValue;

public:
	CPolyZbotwten(CMaxPEFile *pMAxPEFile);
	~CPolyZbotwten(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

//Sneha Kurade
class CPolyDownloaderH : public CPolyBase
{	
	DWORD m_dwOrigFileAEP;

 public:
	CPolyDownloaderH(CMaxPEFile *pMaxPEFile);
	~CPolyDownloaderH(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Swapnil
class CPolySWISYNFOHA : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFilseSize;

public:
	CPolySWISYNFOHA(CMaxPEFile *pMaxPEFile);
	~CPolySWISYNFOHA(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Jay Prakash
class CPolyTrojanGenKD30602080 : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;

public:
	CPolyTrojanGenKD30602080(CMaxPEFile *pMaxPEFile);
	~CPolyTrojanGenKD30602080(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};

class CPolyDelfx : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;

public:
	CPolyDelfx(CMaxPEFile *pMaxPEFile);
	~CPolyDelfx(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};

//Swapnil
class CPolyFUNLOVE : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFilseSize;

public:
	CPolyFUNLOVE(CMaxPEFile *pMaxPEFile);
	~CPolyFUNLOVE(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Jay Prakash
class CPolyTrojanSwisynBNER : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;

public:
	CPolyTrojanSwisynBNER(CMaxPEFile *pMaxPEFile);
	~CPolyTrojanSwisynBNER(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};

//Aniket
class  CPolyAgentES : public CPolyBase
{	
	 DWORD m_dwOrigFileOff;
	 DWORD m_dwStartBuff;
	 DWORD m_dwOrigFileSize;
public:
	CPolyAgentES(CMaxPEFile *pMaxPEFile);
	~CPolyAgentES(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Aniket
class  CPolyVBHN : public CPolyBase
{	
	 DWORD m_dwOrigFileOff;
	 DWORD m_dwOrigFileSize;
public:
	CPolyVBHN(CMaxPEFile *pMaxPEFile);
	~CPolyVBHN(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

//Sneha
class CPolyTrojanAgentRC4 : public CPolyBase
{
      DWORD m_dwOrigFileOff;
      DWORD m_dwOrigFileSize;
public:
      CPolyTrojanAgentRC4(CMaxPEFile *pMaxPEFile);
      ~CPolyTrojanAgentRC4(void);
      DWORD keyBuff[0x100];
      DWORD dwkey[0x10];
      bool FirstKey();
      int DetectVirus(void);
      int CleanVirus(void);
};

//Aniket
class  CPolyVirusShohdi : public CPolyBase
{	
	 DWORD m_dwOrigFileOff;
	 DWORD m_dwOrigFileSize;
public:
	CPolyVirusShohdi(CMaxPEFile *pMaxPEFile);
	~CPolyVirusShohdi(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

// Worm.Win32.Viking.eo [Jay Prakash 27-01-2021]
class CPolyWormVikingEO : public CPolyBase
{
	DWORD m_dwFileSize;
	DWORD m_dwOriginalFileSize;
	DWORD m_dwOriginalFileOffset;
public:
	CPolyWormVikingEO(CMaxPEFile *pMaxPEFile);
	~CPolyWormVikingEO(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

// Virus.WIN32.HLLP.Shodi.a [Jay Prakash 21-09-2021]
class  CPolyVirusShodiA : public CPolyBase
{	
	 DWORD m_dwOrigFileOff;
	 DWORD m_dwOrigFileSize;
public:
	CPolyVirusShodiA(CMaxPEFile *pMaxPEFile);
	~CPolyVirusShodiA(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

// Trojan.Pached.RW [14-04-2022]
class CPolyPatchedRW : public CPolyBase
{
	DWORD m_dwAEPOffset;
	DWORD m_dwVirusSectionOffset;

public:
	CPolyPatchedRW(CMaxPEFile *pMaxPEFile);
	~CPolyPatchedRW(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
	
};