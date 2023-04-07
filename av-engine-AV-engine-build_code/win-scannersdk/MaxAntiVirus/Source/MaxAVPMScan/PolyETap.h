/*======================================================================================
FILE				: PolyETap.h
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
CREATION DATE		: 08 Aug 2012
NOTES				: This is detection module for malware ETap Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int	ETAP_BUFF_SIZE		= 0x1000;
const int	VALID_LAST_SEC_SIZE	= 0xB000;
const BYTE	SEARCH_STRING[2]	= {0xFF, 0x25};
const int	IMPORT_DIR_TABLE	= 1;

enum
{
	CALL_PATCH,
	PUSH_PATCH,
	FIRST_SECTION,
	LAST_SECTION,
	SECOND_SECTION
};

typedef struct _tagETAP_STRUCT
{
	DWORD	dwVirusStart;
	DWORD	dwVirusStartRVA;
	int		iDetectionType;
	DWORD	dwExitProcAdd;
	DWORD	dwPatchAdd;
	DWORD	dwVirusSection;
	DWORD	dwVirusStartAdd;
}ETap_Struct;

class CPolyETap : public CPolyBase
{
	ETap_Struct m_objETapStruct;
	
	int		CheckEtapInstruction();
	int		GetEtapLoopIns(DWORD dwStartLoop, DWORD dwEndLoop);

public:
			CPolyETap(CMaxPEFile *pMaxPEFile);
			~CPolyETap(void);

	int		DetectVirus(void);
};
