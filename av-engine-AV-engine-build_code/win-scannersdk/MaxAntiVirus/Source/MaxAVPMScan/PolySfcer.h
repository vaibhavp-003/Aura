/*======================================================================================
FILE				: PolySfcer.h
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
NOTES				: This is detection module for malware Sfcer Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int SFCER_BUFF_SIZE = 0x100;

enum SFCER_Dec_Type
{
	NO_SFCER_DEC = 0x00,
	DEC_SFCER_ROR,
	DEC_SFCER_ROL,
	DEC_SFCER_XOR,
	DEC_SFCER_ADD,
	DEC_SFCER_SUB
};

struct SFCER_PARAM_STRUCT
{
	BYTE					m_byDecKey;
	BYTE					m_byRORCounter;
	enum SFCER_Dec_Type		eDecryptionType;
};

class CPolySfcer :	public CPolyBase
{
	SFCER_PARAM_STRUCT m_objSfcerParam;

	int GetSfcerParam();

public:
	CPolySfcer(CMaxPEFile *pMaxPEFile);
	~CPolySfcer(void);

	int DetectVirus();
	int CleanVirus();
};

