/*======================================================================================
FILE				: PolyElkern.h
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
NOTES				: This is detection module for malwares Poly Elkern Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int ELKERNC_BUFF_SIZE = 0x200;
const int ELKERNA_BUFF_SIZE = 0x184;

enum ELKERN_INFECTION_TYPE
{
	ELKERN_AB,
	ELKERN_C,
	ELKERN_C1
};

typedef struct
{
	DWORD	dwPatchedOffset;
	WORD	wVirusSection;
	DWORD	dwStartOfVirusCode;
}ELKERN_PARAM,*PELKERN_PARAM;

class CPolyElkern : public CPolyBase
{
	ELKERN_INFECTION_TYPE m_eInfectionType;
	ELKERN_PARAM	m_ElkernParam;
	DWORD			m_dwElkernAOriAEP;

	int		GetElkernAParam();

public:
	CPolyElkern(CMaxPEFile *pMaxPEFile);
	~CPolyElkern(void);
	
	int		DetectVirus(void);
	int		CleanVirus(void);

};
