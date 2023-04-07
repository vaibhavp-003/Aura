/*======================================================================================
FILE				: PolyPolip.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Rupali Sonawane + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Polip Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"
#include "BufferToStructure.h"

const int POLIP_BUFF_SIZE		= 0x400;
const int POLIP_A_NO_OF_PARTS	= 0x10;
const int CALL_BUFF_SIZE		= 0x1500;
const int POLIP_ENCRY_CODE_SIZE = 0x765c;
const int VIRUS_CODE_SIZE		= 0x13B;
const int PATCH_BUFF_SIZE		= 0x7145;
const int BUFF_OFFSET			= 0x517;
const int EXTRA_BYTES			= 0x06;
const int POLIPA_AEP_SEC_BUFF	= 0x1000;

struct POLIP_CONSTANTS_STRUCT
{
	DWORD dwSizeOfDecryptionBuffer;
	DWORD dwDecryptionKey;
	DWORD dwVirtualAddress;
};

class CPolyPolip : public CPolyBase
{
	POLIP_CONSTANTS_STRUCT	m_arrPolipConstants[POLIP_A_NO_OF_PARTS];
	int		m_iNoOfParts;
	DWORD	m_dwVirusCallAddress;
	DWORD	m_dwAEPSecCallAddress;
	bool	m_bCallInAEPSec;
		
	bool	PolipA_ScanVirusSection(WORD wVirusSection, WORD wScanSection, DWORD dwScanStartOffset);
	WORD	GetPolipAVirusSection();
	bool	DecryptPolipAParts();
	BOOL	SortPolipFunctionParameters();
	BOOL	PolipFirstLevelDecryption(BYTE *Buff, DWORD BuffLen, DWORD Key);
	BOOL	DecryptPolipUsingXTEA(unsigned int num_rounds, unsigned long *value, unsigned long key);
	BOOL	PolipSecondLevelDecryption(BYTE *Buff,  DWORD BuffLen);

	int		CheckPolipALoop();
	int		GetPolipParams();
	int		GetOriginalPatchedBytes();

public:
	CPolyPolip(CMaxPEFile *pMaxPEFile);
	~CPolyPolip(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
