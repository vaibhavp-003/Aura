/*======================================================================================
FILE				: PolyVirut.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Virut Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
					  There are four different types of infection pattern in this virus
					  Also hooks the system API like CreateFile, CreateFileEx etc (This part is managed in Memory Scanner)	
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"
#include "BufferToStructure.h"

const int VIRUT_FI_BUFF_SIZE	= 0x1000;
const int VIRUT_GEN_BUFF_SIZE	= 0x1024;
const int VIRUT_VIRUS_CODE_SIZE = 0x7200;

enum Virut_Infection_Type
{
	VIRUT_CE = 1,
	VIRUT_FI,
	VIRUT_GEN
};

typedef struct VirutParameters
{
	int CallFoundLocInBuff;
	int InfectionType;
	DWORD dwModeOffset;
	DWORD dwRvaVirus;
	DWORD dwDecLength;
	DWORD dwVirutKey;
	DWORD dwIncrementalKey;
	DWORD dwVirutMode;
	DWORD InitExitOffset;
	DWORD dwVirusCallOffset;
}VIRUT_PARAM, *P_VIRUT_PARAM;

typedef struct VirutCEParameters
{
	DWORD dwVirusRva;
	DWORD dwVirusBody;
	DWORD dwKey;
	DWORD dwOperation;
	DWORD dwVirusExecStart;
	DWORD dwJumpLocation;
	DWORD dwOriginalAep;
	DWORD dwInitCodeRVA;
	DWORD dwType;
}VIRUTCE_PARAM, *P_VIRUTCE_PARAM;

class CPolyVirut : public CPolyBase
{
	CBufferToStructure		m_objVirutGenParam;
	Virut_Infection_Type	m_eInfectionType;
	bool	m_bPolyCleanFlag;
	DWORD   m_dwOverlaySize;
	DWORD   m_dwInitLen;

	// Virut CE
	VIRUTCE_PARAM VirutCEParam;
	DWORD	m_dwVirusRva, m_dwVirusBody, m_dwKey, m_dwOperation, m_dwVirusExecStart, m_dwJumpLocation, m_dwOriginalAep, m_dwType, m_dwInitCodeRVA;

	int		DetectVirutCE();
	int		DetectVirut_CE_LastSectionAepInit(DWORD dwDeadcode);
	int		DetectVirut_CE_AepInit();
	int		DetectVirutCE_JumpPatch();
	int     DetectVirutCE_DeadCode2();

	DWORD	VirutCE_CheckForJumpBytes(DWORD dwStartLoc, DWORD dwAEP, DWORD dwJmpLoc, DWORD dwImageLoc, DWORD dwJumpRVA);
	int		GetSetJumpBytes(BOOL bWrite, DWORD dwPos, DWORD dwStartLoc, DWORD dwJmpLocn, DWORD dwImgageLocn, DWORD *dwFoundLoc);
	DWORD	AllocateBuffer(BYTE **pbBuffer );
	DWORD	DecryptBuffer(DWORD dwOffSet, BYTE *pBuffer, DWORD *pTotalDecypt);
	int		NewGetSetJumpBytes(BOOL bWrite, DWORD dwPos, DWORD *dwFoundLoc);
	bool	IsValidVirusCode(DWORD dwVirusRva);
	int		GetVirutCEAEPEx_New(DWORD *dwVirusCodeOffset, DWORD *pOriginalAEP, DWORD dwDeadcode);
	int		GetVirutCEParamEx(DWORD dwJumpOffset, DWORD *pJumpOffSet, int iBufIndex);
	int		GetVirutCEAEPEx(DWORD dwSize, DWORD dwExecStart, DWORD dwVirusBase, DWORD *pOriginalAEP);
	int		CleanVirutCE();
	DWORD	GetJumps(BYTE *byBuffer, DWORD dwNoBytesRead, DWORD dwBufferReadOffset, WORD wCallToSection, bool bIsRead = false);

	// Virut File infectors
	DWORD	m_dwVirutFIOriginalAEP;
	int		DetectVirutFileInfector();
	int		GetVirutFIParams(); 
	int		CleanVirutFileInfector();

	//Virut.Gen
	int     NonRepairablefile();
	int		DetectVirutGen();
	int     GetVirutGenType();
	int     DetectVirutGenAepInit();
	int		DetectVirutGenDeadCode();
	int		DetectVirutGenOverlyInit();
	int     DetectVirutGenCallPatchInit();
	int		DetectVirutGenOverlayInfection(DWORD &dwCallRVA);
	int		DetectVirutGenCallPatch(DWORD dwFoundOffset, DWORD dwDistFromAEP, DWORD &dwCallRVA);
	int		GetVirutGenParams(BYTE *pBuffer, VIRUT_PARAM &objVirutParam); 
	int		GetVirutGenDeadInitCodeParam(BYTE *pBuffer, DWORD dwBufferSize); 
	int		GetVirutGenDeadDecCodeParam(BYTE *pBuffer, DWORD dwBufferSize, bool bCheckCall = true);
	bool	DetectVirutGenSig(VIRUT_PARAM objVirutParams);
	bool	FindVirutGenSig(BYTE *pBuffer, DWORD dwBuffSize);
	void	DecryptVirutGen(BYTE *pBuffer, DWORD dwDecLength, VIRUT_PARAM *pVirutParams);
	 
	int		CleanVirutGen();
	int		CleanVirutGenAEPInit(P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset, WORD wVirusCodeSecNo);
	int		CleanVirutGenCallPatch(P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset, WORD wVirusCodeSecNo);
	int		CleanVirutGenOverlay(P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset);
	int		CleanVirutGenDeadCode(DWORD dwVirusOffset);
	
	public:
	CPolyVirut(CMaxPEFile *pMaxPEFile, bool bPolyCleanFlag);
	~CPolyVirut(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};

