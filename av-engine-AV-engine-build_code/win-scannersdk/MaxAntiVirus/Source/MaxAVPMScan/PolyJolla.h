/*======================================================================================
FILE				: PolyJolla.h
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
NOTES				: This is detection module for malware Jolla Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"
#define JOLLA_BUFF_SIZE 0x1100

enum VIRUS_JOLLA
{
	VIRUS_JOLLA_SINGLESEC = 0,
	VIRUS_JOLLA_DEADCODE,
	VIRUS_JOLLA_A
};

class CPolyJolla : public CPolyBase
{
	VIRUS_JOLLA m_eJollaType;

	DWORD	m_dwOriginalAEP;
	WORD	m_wSectionsToTrucate;
	DWORD	m_dwReplaceOff;
	DWORD	m_dwReplaceData;
	DWORD	m_dwTruncateOffset;	

	bool	GetPatchedData();
	bool	GetTruncateOffset();
	bool	DetectDeadCode();
	int		DetectJollaSS();
	int		DetectJolla();

public:
	CPolyJolla(CMaxPEFile *pMaxPEFile);
	~CPolyJolla();

	int		DetectVirus(void);
	int		CleanVirus(void);
};