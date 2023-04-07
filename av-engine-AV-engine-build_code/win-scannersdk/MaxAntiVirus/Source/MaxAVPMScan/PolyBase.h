/*======================================================================================
FILE				: PolyBase.h
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
NOTES				: This is Parent class for all virus classes
					  Also contains detection and repair routines for small malwares	
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include <stdio.h>
#include "pch.h"
#include "Variables.h"
#include "MaxDisassem.h"
#include "U2U.h"
#include "MaxPEFile.h"
#include "Emulate.h"
#include "SemiPolyDBScn.h"

const int MAX_INSTRUCTION_LEN	= 0x20;
const int MAX_ALLOC_SIZE		= 0x10000;
const int E8_INSTRUCTION_SIZE	= 0x05;
const int BOUND_IMP_TABLE_IDX	= 11;

enum DEC_TYPE
{
	NO_DEC_FOUND,
	DEC_ADD,
	DEC_SUB,
	DEC_XOR,
};

class CPolyBase
{
protected:
	CMaxPEFile		*m_pMaxPEFile;	
	CMaxDisassem	m_objMaxDisassem;

	IMAGE_SECTION_HEADER *m_pSectionHeader;
	
	DWORD	m_dwAEPMapped;
	DWORD	m_dwAEPUnmapped;
	DWORD	m_dwImageBase;
	WORD	m_wAEPSec;
	WORD	m_wNoOfSections;
	
	BYTE	*m_pbyBuff;
	DWORD	m_dwNoOfBytes;

	DWORD	m_dwInstCount;	
	CU2U	m_arrPatchedCallOffsets;

	DWORD	Rva2FileOffsetEx(DWORD dwRva, WORD *pRVASection);
	bool	GetBuffer(DWORD dwOffset, DWORD dwNumberOfBytesToRead, DWORD dwMinBytesReq = 0x00);
	DWORD	MakeDword(char *pString,  char chSearch);
	bool	CheckForZeros(DWORD dwReadOffset, DWORD dwNumberOfBytes);
	int		CheckPnuemonics(BYTE *pBuffer, DWORD dwModeOffset, DWORD dwInstructionCount, char *Opcode, DWORD opLength, char *PnuemonicsToSearch );
	bool	OffSetBasedSignature(BYTE *byteSig,DWORD dwSizeofSig,DWORD *dwIndex);
	bool	GetPatchedCalls(DWORD dwSearchStartAddress, DWORD dwSearchEndAddress, WORD wCallToSection, bool bSearchForE9 = false, bool bGetAllCalls = false, bool bGetFirstPatchedCall = false);
	
	DWORD	FindResourceEx(LPCTSTR lpstNameID,DWORD dwRead) ;
	int		FindRes(LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize) ;
	
public:
	CPolyBase(CMaxPEFile *pMaxPEFile);
	virtual ~CPolyBase(void);
	
	TCHAR	m_szVirusName[MAX_VIRUS_NAME];
	int		HighLevelDetection();
	int		DetectNonRepairableVirus(LPCTSTR pFilename);

	bool	CheckSigInBuffer(DWORD	dwBuffStartPos, DWORD	dwBuffSize2Read, LPCTSTR lpszSig2Check);

	// Function scans the file to check if the file is infected by virus
	virtual int DetectVirus(void);
	virtual int CleanVirus(void);
};

class CPolySatir: public CPolyBase
{
	DWORD	m_dwDecKey;
	DWORD	m_dwVirusStartOffset;
	
public:
	CPolySatir(CMaxPEFile *pMaxPEFile);
	~CPolySatir(void);

	int DetectVirus();
	int CleanVirus();
};
/*
class CPolyOporto:	public CPolyBase
{
	DWORD	m_dwDecKey;
	DWORD	m_dwVirusStartOffset;

public:
	CPolyOporto(CMaxPEFile *pMaxPEFile);
	~CPolyOporto(void);

	int DetectVirus();
	int CleanVirus();
};
*/
class CPolyKenston: public CPolyBase
{
	DWORD m_dwOriginalAEP;

public:
	CPolyKenston(CMaxPEFile *pMaxPEFile);
	~CPolyKenston(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolyCrazyPrier: public CPolyBase
{
public:
	CPolyCrazyPrier(CMaxPEFile *pMaxPEFile);
	~CPolyCrazyPrier(void);	

	int DetectVirus();
	int CleanVirus();
};

class CPolyVB: public CPolyBase
{
	DWORD m_dwCallAddr;
	DWORD m_dwOriPatchOffset;

public:
	CPolyVB(CMaxPEFile *pMaxPEFile);
	~CPolyVB(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyKanban: public CPolyBase
{
public:
	CPolyKanban(CMaxPEFile *pMaxPEFile);
	~CPolyKanban(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyKoru: public CPolyBase
{
	DWORD m_dwKey;
	DWORD m_dwJumpOffset;

	bool GetKoruParam();

public:
	CPolyKoru(CMaxPEFile *pMaxPEFile);
	~CPolyKoru(void);
	
	int DetectVirus();
	int CleanVirus();
};

class CPolyInvictus: public CPolyBase
{
	DWORD	m_dwTruncationOffSet;

public:
	CPolyInvictus(CMaxPEFile *pMaxPEFile);
	~CPolyInvictus(void);

	int DetectVirus();
	int CleanVirus();
};

const int HIV_BUFF_SIZE			= 0x200;
const int HIV_VIRUS_CODE_SIZE	= 0x4000;

class CPolyHIV: public CPolyBase
{
	bool m_bFoundCallPatched;
	DWORD m_dwVirusStartOffset;
	DWORD m_dwCallPatchAdd;
	DWORD m_dwPatchDataOff;
	DWORD m_dwOriBytesOffset;
	
	bool CheckSignature();
	
public:
	CPolyHIV(CMaxPEFile *pMaxPEFile);
	~CPolyHIV(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyCalm: public CPolyBase
{ 
	bool CheckSignature();

public:
	CPolyCalm(CMaxPEFile *pMaxPEFile);
	~CPolyCalm(void);

	int DetectVirus();
	int CleanVirus();
};

const int MOGUL_BUFF_SIZE = 0x2000;

class CPolyMogul : public CPolyBase
{
	DWORD m_dwVirusStartOffset;
    DWORD m_dwOriginalAEP;

	bool GetMogulParam(DWORD dwVirusStartRVA);

public:
	CPolyMogul(CMaxPEFile *pMaxPEFile);
	~CPolyMogul(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolySwaduk: public CPolyBase
{
	DWORD m_dwJmpOffset;
	
public:
	CPolySwaduk(CMaxPEFile *pMaxPEFile);
	~CPolySwaduk(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolySuperThreat: public CPolyBase
{
	DWORD	m_dwOriPatchOffset;
	BYTE	m_byXorKey;
	int		m_iJmpCnt;

	bool	GetSuperThreatParam();

public:
	CPolySuperThreat(CMaxPEFile *pMaxPEFile);
	~CPolySuperThreat(void);
	
	int		DetectVirus();
	int		CleanVirus();
};

class CPolyKillFile: public CPolyBase
{	
	DWORD	m_dwJmpPatchOffset;
	DWORD	m_dwMapVirOffset;
	DWORD	m_dwMapSecPatOff;

	bool	GetKillFileParameters();

public:
	CPolyKillFile(CMaxPEFile *pMaxPEFile);
	~CPolyKillFile(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class CPolyDudra : public CPolyBase
{
	DWORD	m_dwOriginalAEP;

public:
	CPolyDudra(CMaxPEFile *pMaxPEFile);
	~CPolyDudra(void);
	
	int		DetectVirus();
	int		CleanVirus();
};

class CPolyBasket: public CPolyBase
{	
	DWORD m_dwCallPatchAdd;
	DWORD m_dwVirusStartOffset;

public:
	CPolyBasket(CMaxPEFile *pMaxPEFile);
	~CPolyBasket(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class CPolyLazyMin: public CPolyBase
{	
	DWORD	m_dwKey;

public:
	CPolyLazyMin(CMaxPEFile *pMaxPEFile);
	~CPolyLazyMin(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

const int DEADCODE_BUFF_SIZE = 0x900;
class CPolyDeadCode: public CPolyBase
{
	DWORD	m_dwDecKey_1;
	DWORD	m_dwDecKey_2;
	DWORD	m_dwVirusJumpOffset;
	DWORD   m_dwNoofBytetoReplace;
	DWORD   m_dwIndex;
	
	bool GetDeadCodeParam();
	
public:
	CPolyDeadCode(CMaxPEFile *pMaxPEFile);
	~CPolyDeadCode(void);

	int DetectVirus();
	int CleanVirus();
	bool Decryption(DWORD dwDecStartOffset, DWORD dwOffset, DWORD dwDecrypSize, bool bRotateLeft);
};

class CPolyPartriot : public CPolyBase
{
	DWORD	m_dwKey;
	DWORD	m_dwVirusEndAddr;
	DWORD	m_dwVirusStartOffset;
	
	bool	GetDecryptionData();

public:
	CPolyPartriot(CMaxPEFile *pMaxPEFile);
	~CPolyPartriot();

	int		DetectVirus();
	int		CleanVirus();
	
};


const int KRIZ_COUNTER = 0xFC4;

class CPolyKriz : public CPolyBase
{
	DWORD	m_dwOriAEP;
	int DetectKriz();

public:
	CPolyKriz(CMaxPEFile *pMaxPEFile);
	~CPolyKriz(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolyZapRom : public CPolyBase
{
	DWORD m_dwOriByteOffset;
	DWORD m_dwCount;

	DWORD GetOriginatData(DWORD);
public:

	CPolyZapRom (CMaxPEFile *pMaxPEFile);
	~CPolyZapRom(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyEvol : public CPolyBase
{
	bool CheckSignature(DWORD);	

public:

	CPolyEvol (CMaxPEFile *pMaxPEFile);
    ~CPolyEvol (void);

	int DetectVirus();
	int CleanVirus();
};

class CPolyMerinos: public CPolyBase
{	
	DWORD m_dwOrgAEPBytesOffset;

public:
	CPolyMerinos(CMaxPEFile *pMaxPEFile);
	~CPolyMerinos(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class CPolyHalen : public CPolyBase
{
	DWORD		m_DecSize;
	DWORD		m_dwAddKey;
	DWORD		m_dwOffset;
	DWORD		m_dwReadOffset;

	int CleanHalen(void);

public:
	CPolyHalen(CMaxPEFile *pMaxPEFile);
	~CPolyHalen(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyGremo : public CPolyBase
{	
	DWORD m_dwReplaceOffSet;
	DWORD m_dwJumpFromOffset;
	DWORD m_dwCallAddr;

public:
	CPolyGremo(CMaxPEFile * pMaxPEFile);
	~CPolyGremo(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

const int PADDI_BUFF_SIZE = 0x800;

class CPolyPaddi : public CPolyBase
{
	DWORD 	m_dwOriginalAEP;
	int		DetectPaddi(void);

public:
	CPolyPaddi(CMaxPEFile *pMaxPEFile);
	~CPolyPaddi(void);

	int		DetectVirus(void);
	int		CleanVirus(void);	
};

class CPolyModrin: public CPolyBase
{
	DWORD m_dwVirusStartOffset;
	BYTE m_bVariant;

public:
	CPolyModrin(CMaxPEFile *pMaxPEFile);
	~CPolyModrin();
	
	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolySmash: public CPolyBase
{	
	DWORD m_dwOffset;
	
public:
	CPolySmash(CMaxPEFile *pMaxPEFile);
	~CPolySmash(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

class CPolyBabylonia: public CPolyBase
{
	DWORD m_dwVirusStartOffset;
	DWORD m_dwCallPatchAdd;

public:
	CPolyBabylonia(CMaxPEFile *pMaxPEFile);
	~CPolyBabylonia();
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyFono : public CPolyBase
{	
	DWORD m_dwOrigAep;

public:
	CPolyFono(CMaxPEFile *pMaxPEFile);
	~CPolyFono(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};


class CPolySpiker: public CPolyBase
{
	DWORD m_dwVirusStartOffset;
	DWORD m_dwDllStartOffset;

public:
	CPolySpiker(CMaxPEFile *pMaxPEFile);
	~CPolySpiker();
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyDieHard: public CPolyBase
{
public:
	CPolyDieHard(CMaxPEFile *pMaxPEFile);
	~CPolyDieHard();

	int DetectVirus();
	int CleanVirus();
};

class CPolyZero: public CPolyBase
{
public:
	CPolyZero(CMaxPEFile *pMaxPEFile);
	~CPolyZero();

	int DetectVirus();
	int CleanVirus();
};

class CPolyLuna: public CPolyBase
{
	DWORD   m_dwOriAEP;

public:
	CPolyLuna(CMaxPEFile *pMaxPEFile);
	~CPolyLuna();
	
	int DetectVirus();
	int CleanVirus();
};

enum MARBURG_DEC_TYPE
{
   NO_MARBURG_KEY_FOUND = 0x00,
   MARBURG_SUB_BYTE,
   MARBURG_ADD_BYTE,
   MARBURG_XOR_BYTE,
   MARBURG_XOR_DWORD,
   MARBURG_ADD_DWORD,
   MARBURG_SUB_DWORD
};

class CPolyMarburg : public CPolyBase
{
	MARBURG_DEC_TYPE	m_eDecType;
	DWORD				m_dwVirusOffset;
	DWORD				m_dwIndex;

	bool CheckSignature(DWORD dwJmpOffset);

public :
	CPolyMarburg(CMaxPEFile *pMaxPEFile);
	~CPolyMarburg(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolyGodog : public CPolyBase
{	
	DWORD m_dwOffset;

public:
	CPolyGodog(CMaxPEFile *pMaxPEFile);
	~CPolyGodog(void);
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyXtail: public CPolyBase
{
	BYTE m_byType;
		
public:
	CPolyXtail(CMaxPEFile *pMaxPEFile);
	~CPolyXtail();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyFiasko: public CPolyBase
{
	DWORD m_dwOriginalAEP;
		
public:
	CPolyFiasko(CMaxPEFile *pMaxPEFile);
	~CPolyFiasko();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyRubashka: public CPolyBase
{
		
	DWORD	m_dwPushAdd, m_dwDecStart, m_dwDecValue, m_dwDecCnt;
	bool	GetRubashkaParameters(bool bCheckCntVal = false);
public:
	CPolyRubashka(CMaxPEFile *pMaxPEFile);
	~CPolyRubashka();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyAgentCE: public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwOffset;
	
public:
	CPolyAgentCE(CMaxPEFile *pMaxPEFile);
	~CPolyAgentCE();
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyYounga : public CPolyBase
{	
public:

	CPolyYounga(CMaxPEFile *pMaxPEFile);
    ~CPolyYounga(void);

	int DetectVirus();
	int CleanVirus();
};

class CPolyHPS: public CPolyBase
{
	DWORD	m_dwKey;
	DWORD	m_dwOffset;
	BYTE	m_bDecType;
	
public:
	CPolyHPS(CMaxPEFile *pMaxPEFile);
	~CPolyHPS();
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyImplinker: public CPolyBase
{	
	DWORD m_dwImportoffset;
	DWORD m_dwpathOffset;

public:
	CPolyImplinker(CMaxPEFile *pMaxPEFile);
	~CPolyImplinker();
	
	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyKarachun: public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwNoPatchedBytes;

public:
	CPolyKarachun(CMaxPEFile *pMaxPEFile);
	~CPolyKarachun();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyChop : public CPolyBase
{
	DWORD   m_dwVirusStart;
	DWORD   m_dwOriAEPOffset;
	
	bool DecrypBuff(DWORD, char);

public:
	CPolyChop(CMaxPEFile *pMaxPEFile);
	~CPolyChop();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyBytesv: public CPolyBase
{
	DWORD m_dwOriginalAEP;
	  
 public:
	CPolyBytesv(CMaxPEFile * pMaxPEFile);
	~CPolyBytesv(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyDugert : public CPolyBase
{
 public:
	CPolyDugert(CMaxPEFile * pMaxPEFile);
	~CPolyDugert(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyPoson4367: public CPolyBase
{
	DWORD m_dwVirusOff;
	DWORD m_dwDecStart;
	DWORD m_dwVirusFileOff;
public:
	CPolyPoson4367(CMaxPEFile *pMaxPEFile);
	~CPolyPoson4367();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyMeginA: public CPolyBase
{
	DWORD m_dwOriginalAEP;
	DWORD m_dwJmpOff;
	DWORD m_dwImportRVA;
	
public:
	CPolyMeginA(CMaxPEFile *pMaxPEFile);
	~CPolyMeginA();

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyAgentFT : public CPolyBase
{ 
	DWORD m_dwOriginalFileOffset;
	DWORD m_dwOriginalFileSize;
	DWORD m_dwFillZeroOff;

public:
	CPolyAgentFT(CMaxPEFile *pMaxPEFile);
	~CPolyAgentFT(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

class CPolyRiskToolBitMiner : public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD m_dwOrigFileSize;
	bool m_bInfectionCleaned;
	DWORD m_SIGNOff;

public:
	CPolyRiskToolBitMiner(CMaxPEFile *pMaxPEFile);
	~CPolyRiskToolBitMiner(void);

	int DetectVirus(void);
	int CleanVirus(void);
};

/*
class CPolyInfector : public CPolyBase
{ 
	DWORD m_dwOrigAEP ;
	DWORD	m_dwCharBuffer;

public:
	CPolyInfector(CMaxPEFile *pMaxPEFile);
	~CPolyInfector(void);

	int DetectVirus(void);
	int CleanVirus(void);
};
*/


class CPolyTrojangenerickdz:public CPolyBase
{
	DWORD m_dwOrigFileOff;
	DWORD M_dwVirusData;
public:
	CPolyTrojangenerickdz(CMaxPEFile *pMAxPEFile);
	~CPolyTrojangenerickdz(void);

	int DetectVirus(void);
	int CleanVirus(void);
};
