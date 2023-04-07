/*======================================================================================
FILE				: PolyNimnul.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Yash Gund + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 05 Mar 2011
NOTES				: This is detection module for malware Nimnul Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 18 Aug 2011 : Added New Function for Nimnul.D Detection 
					  18 Aug 2011 : Added New Function for Nimnul.C Detection	
=====================================================================================*/
#pragma once
#include "polybase.h"

const int NIMNUL_BUFF_SIZE		= 0x600;
const int NIMNUL_AEPBUFF_SIZE	= 11;
const int NIMNUL_JMPBUFF_SIZE	= 6;
const int NIMNUL_C_AEPOFFSET	= 0x27E;
const int NIMNUL_D_AEPOFFSET	= 0x268;
const int NIMNUL_F_AEPOFFSET	= 0x064;

/*
typedef struct _NIMNUL_E_PARAM
{
	DWORD	dwNimnulType;
	DWORD	dwOrgDataOffSet;
	DWORD	dwFirstPatchOff;
	DWORD	dwSecPatchOff;
	DWORD	dwPatchDiff;
	DWORD	dwPatchSize;
	DWORD	dwResSize;
}NIMNUL_E_PARAM,*LPNIMNUL_E_PARAM;
*/
typedef struct _NIMNUL_E_PARAM
{
	DWORD	dwNimnulType;
	DWORD	dwResOffSet;
	DWORD	dwFPatchDisplacement;
	DWORD	dwSPatchDisplacement;
	DWORD	dwPatchDiff;
	DWORD	dwFPatchSize;
	DWORD	dwResSize;
}NIMNUL_E_PARAM,*LPNIMNUL_E_PARAM;

class CPolyNimnul : public CPolyBase
{
	int		DetectNimnul(DWORD dwAEP, WORD wAEPSection, bool bSecondAttempt = false);
	bool	GetNimnulGenParameter(DWORD *dwFirst, DWORD *dwSecond);
	DWORD	DetectNimnulC();
	DWORD	DetectNimnulD();
	BOOL	DetectNimnulE();
	DWORD	DetectNimnulF();
	DWORD	IsRequiredResource(DWORD dwBaseResAddrs, int iResCount, DWORD &dwResSize);
	BOOL	bIsNimnulE;


	NIMNUL_E_PARAM	m_stParamas;

public:
	CPolyNimnul(CMaxPEFile *pMaxPEFile);
	~CPolyNimnul(void);
	
	DWORD m_dwOriginalNimnulAEP;
	int DetectVirus(void);
	int CleanVirus(void);
	int CleanNimnulE(void);

	WORD	m_wNoOfSec;
	DWORD	m_dwOriginalOffset;
};
