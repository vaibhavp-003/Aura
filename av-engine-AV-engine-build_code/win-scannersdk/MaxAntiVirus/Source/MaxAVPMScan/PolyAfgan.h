/*======================================================================================
FILE				: PolyAfgan.h
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
NOTES				: This is detection module for malwares Virus.Afgan Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int AFGAN_BUFF_SIZE = 0x100;

typedef struct _tag_AFGAN_STRUCT
{
	DWORD dwOriginalBytesOffset;
	DWORD dwPatchedCodeSizeOffset;
}Afgan_struct;

class CPolyAfgan : public CPolyBase
{
	Afgan_struct m_oAfgan_Params;
	
public:
	CPolyAfgan(CMaxPEFile *pMaxPEFile);
	~CPolyAfgan(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
