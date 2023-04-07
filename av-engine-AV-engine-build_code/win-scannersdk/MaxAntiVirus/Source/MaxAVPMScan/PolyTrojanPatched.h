/*======================================================================================
FILE				: PolyTrojanPatched.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Trojan.Patched Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int PATCHED_BUFF_SIZE		= 0x250;
const int TROJAN_PATCHED_LP		= 0x1E;
const int AEP_BYTES_OFFSET		= 0x15;
const int PATCHED_LP_BYTES		= 0x0E;
const int PATCHED_LP_SCAN_BYTES	= 0x300;
const int PATCHED_LW_BYTES		= 0x300;
const int PATCHED_EH_BUFF_SIZE	= 0x200;
const int PATCH_BZ_BUFF_SIZE	= 0x1E;
const int PATCH_KZ_BUFF_SIZE	= 0x35;

#define PATCHED_KL_SIG "hlp.dat"

enum PATCHED_VIRUS
{
	TrojanPatchedlp = 0,
	TrojanPatchedkl,
	TrojanPatchedJa,	
	TrojanPatchedLK,	
	TrojanPatchedMK,
	TrojanPatchedEH,
	TrojanPatchedGO,
	TrojanPatchedJI,
	TrojanPatchedDR,
	TrojanPatchedBZ,
	TrojanPatchedJ,
	TrojanPatchedJH,
	TrojanPatchedHL,
	TrojanPatchedDQ,
	TrojanPatchedOD,
	TrojanPatchedDY,
	TrojanPatchedAL,
	TrojanPatchedBJ,
	TrojanPatchedBH,
	TrojanPatchedOK,
	TrojanPatchedDK,
	TrojanPatchedMU,
	TrojanPatchedOM,
	TrojanPatchedDO,
	TrojanPatchedMJ,
	TrojanPatchedHG,
	TrojanPatchedHZ,
	TrojanPatchedHP,
	TrojanPatchedHI,
	TrojanPatchedDZ,
	TrojanPatchedKa
};

struct PATCHEDKL_STRUCT
{
	DWORD dwOriginalBytesOffset;
	DWORD dwSizeOfBuff;
};

class CPolyTrojanPatched : public CPolyBase
{
	DWORD	m_dwOriginalAEP; 
	DWORD	m_dwDLLFileOffset;
	DWORD   m_dwReplaceOffSet;
	DWORD   m_dwDataAddr;
	DWORD	m_dwTruncateOffset;
	DWORD	m_dwNoOfbyteToRead;
	DWORD	m_dwOriData;
	DWORD	m_dwJumpFrom;
	DWORD	m_dwPatched_KZ_Offset;
	DWORD	m_dwPatched_KZ_DWORD;
	DWORD	m_dwNoOfByteReplace;
	DWORD	m_dwNoOfbyteToFill;
	DWORD	m_dwOriByteOffset;
	DWORD	m_dwSize;
	DWORD	m_dwImportTableAdd;

	PATCHEDKL_STRUCT	m_PatchedlpStruct;
	PATCHED_VIRUS		m_eVirusDetected;

	int		DetectTrojanPatchedlp();
	int		DetectTrojanPatchedkl();
	int		DetectTrojanPatchedJa();
	int		DetectTrojanPatchedLK();
	int		DetectTrojanPatchedMK();
	int		DetectTrojanPatchedEH();
	int		DetectTrojanPatchedGO();
	int		DetectTrojanPatchedJI();
	int		DetectTrojanPatchedDR();
	int		DetectTrojanPatchedBZ();
	int		DetectTrojanPatchedJ();
	int		DetectTrojanPatchedJH();
	int		DetectTrojanPatchedHL();
	int		DetectTrojanPatchedDQ();
	int		DetectTrojanPatchedOD();
	int		DetectTrojanPatchedDY();
	int		DetectTrojanPatchedAL();
	int		DetectTrojanPatchedBJ();
	int		DetectTrojanPatchedBH();
	int		DetectTrojanPatchedOK();
	int		DetectTrojanPatchedDK();
	int		DetectTrojanPatchedMU();
	int		DetectTrojanPatchedOM();
	int		DetectTrojanPatchedLQ();
	int		DetectTrojanPatchedDO();
	int		DetectTrojanPatchedMJ();
	int		DetectTrojanPatchedHB();
	int		DetectTrojanPatchedHG();
	int		DetectTrojanPatchedHZ();
	int		DetectTrojanPatchedHP();
	int		DetectTrojanPatchedHI();
	int		DetectTrojanPatchedDZ();
	int		DetectTrojanPatchedMY();
	int		DetectTrojanPatchedKa();

	int		CleanTrojanPatchedlp();
	int		CleanTrojanPatchedkl();
	int		CleanTrojanPatchedJa();
	int		CleanTrojanPatchedLK();
	int		CleanTrojanPatchedMK();
	int		CleanTrojanPatchedEH();
	int		CleanTrojanPatchedGO();
	int		CleanTrojanPatchedJI();
	int		CleanTrojanPatchedDR();
	int		CleanTrojanPatchedBZ();
	int		CleanTrojanPatchedJ();
	int		CleanTrojanPatchedJH();
	int		CleanTrojanPatchedHL();
	int		CleanTrojanPatchedDQ();
	int		CleanTrojanPatchedOD();
	int		CleanTrojanPatchedDY();
	int		CleanTrojanPatchedAL();
	int		CleanTrojanPatchedBJ();
	int		CleanTrojanPatchedBH();
	int		CleanTrojanPatchedOK();
	int		CleanTrojanPatchedDK();
	int		CleanTrojanPatchedMU();
	int		CleanTrojanPatchedOM();
	int		CleanTrojanPatchedDO();
	int		CleanTrojanPatchedMJ();
	int		CleanTrojanPatchedHG();
	int		CleanTrojanPatchedHZ();
	int		CleanTrojanPatchedHP();
	int		CleanTrojanPatchedHI();
	int		CleanTrojanPatchedDZ();
	int		CleanTrojanPatchedKa();

	bool	GetTrojanPatchedklParams(DWORD dwBytesRead);
	bool	GetTrojanPatchedJaParam();
	bool	GetTrojanPatchedEHParam();
	bool	GetTrojanPatchedHLParam();
	bool	GetTrojanPatchedODParam();
	bool	GetTrojanPatchedOKParam();
	bool	GetTrojanPatchedDKParam();
	bool	GetTrojanPatchedMUParam();	
	bool	GetTrojanPatchedDOParam();	
	bool	CheckTrojanPatchedMU();

public:
	CPolyTrojanPatched(CMaxPEFile *pMaxPEFile);
	~CPolyTrojanPatched(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
