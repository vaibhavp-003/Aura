/*======================================================================================
FILE				: PolyThorin.h
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
NOTES				: This is detection module for malware Thorin Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int THORIN_BUFF_SIZE = 0x3300;

typedef enum eTHORIN_Decryption_Mode
{
	ADD_DWORD = 1,
	SUB_DWORD,
	XOR_DWORD
};

struct STRUCT_THORIN_DECRYPTION_PARAMS
{
	DWORD	dwDecryptionOffset;
	DWORD	dwDecryptionKey;
	DWORD	dwDecryptionCounter;
	DWORD	dwNextLoopOffset;
	DWORD	dwSecondaryDecryptionCounter;
	DWORD   dwDecryptionLoopBreakingValue;
	DWORD   dwSecDecrptionInnerLoopKey1;
	DWORD   dwSecDecrptionInnerLoopKey2;
	eTHORIN_Decryption_Mode	eOperation;
};

class CPolyThorin : public CPolyBase
{
	STRUCT_THORIN_DECRYPTION_PARAMS m_stDecryptionParams;

	int		ThorinPrimaryDetection(void);
	int		ThorinDecryption(void);
	int		ThorinSecondaryDecryption();

public:
	CPolyThorin(CMaxPEFile *pMaxPEFile);
	~CPolyThorin(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
